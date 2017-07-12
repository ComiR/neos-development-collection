<?php
namespace Neos\Neos\Domain\Strategy;

/*
 * This file is part of the Neos.Neos package.
 *
 * (c) Contributors of the Neos Project - www.neos.io
 *
 * This package is Open Source Software. For the full copyright and license
 * information, please view the LICENSE file which was distributed with this
 * source code.
 */

use Neos\ContentRepository\Domain\Model\NodeData;
use Neos\ContentRepository\Domain\Model\NodeInterface;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Persistence\PersistenceManagerInterface;
use Neos\Flow\Security\Context as SecurityContext;
use Neos\Neos\Domain\Service\SiteService;
use Neos\Utility\TypeHandling;
use Neos\Media\Domain\Model\AssetInterface;
use Neos\Media\Domain\Model\Image;
use Neos\Media\Domain\Strategy\AbstractAssetUsageStrategy;
use Neos\Neos\Domain\Model\Dto\AssetUsageInNodeProperties;
use Neos\Neos\Domain\Repository\SiteRepository;
use Neos\Neos\Service\UserService;
use Neos\Eel\FlowQuery\FlowQuery;
use Neos\Neos\Controller\CreateContentContextTrait;
use Neos\ContentRepository\Domain\Factory\NodeFactory;
use Neos\ContentRepository\Domain\Repository\NodeDataRepository;
use Neos\Neos\Domain\Service\UserService as DomainUserService;

/**
 * @Flow\Scope("singleton")
 */
class AssetUsageInNodePropertiesStrategy extends AbstractAssetUsageStrategy
{
    use CreateContentContextTrait;

    /**
     * @Flow\Inject
     * @var NodeDataRepository
     */
    protected $nodeDataRepository;

    /**
     * @Flow\Inject
     * @var SiteRepository
     */
    protected $siteRepository;

    /**
     * @Flow\Inject
     * @var NodeFactory
     */
    protected $nodeFactory;

    /**
     * @Flow\Inject
     * @var UserService
     */
    protected $userService;

    /**
     * @Flow\Inject
     * @var DomainUserService
     */
    protected $domainUserService;

    /**
     * @var array
     */
    protected $firstlevelCache = [];

    /**
     * @Flow\Inject
     * @var PersistenceManagerInterface
     */
    protected $persistenceManager;

    /**
     * @Flow\Inject
     * @var SecurityContext
     */
    protected $securityContext;

    /**
     * Returns an array of usage reference objects.
     *
     * @param AssetInterface $asset
     * @return array<\Neos\Neos\Domain\Model\Dto\AssetUsageInNodeProperties>
     * @throws \Neos\ContentRepository\Exception\NodeConfigurationException
     */
    public function getUsageReferences(AssetInterface $asset)
    {
        $assetIdentifier = $this->persistenceManager->getIdentifierByObject($asset);
        if (isset($this->firstlevelCache[$assetIdentifier])) {
            return $this->firstlevelCache[$assetIdentifier];
        }

        $relatedNodes = [];
        foreach ($this->getRelatedNodes($asset) as $relatedNodeData) {
            /** @var NodeData $relatedNodeData */
            $context = $this->createContextMatchingNodeData($relatedNodeData);
            $node = $this->nodeFactory->createFromNodeData($relatedNodeData, $context);
            $this->securityContext->withoutAuthorizationChecks(function () use ($node, &$documentNode) {
                $flowQuery = new FlowQuery([$node]);
                /** @var NodeInterface $documentNode */
                $documentNode = $flowQuery->closest('[instanceof Neos.Neos:Document]')->get(0);
            });

            $site = $context->getCurrentSite();
            $accessible = $this->domainUserService->currentUserCanReadWorkspace($relatedNodeData->getWorkspace());
            $relatedNodes[] = new AssetUsageInNodeProperties($asset, $site, $documentNode, $node, $accessible);
        }

        $this->firstlevelCache[$assetIdentifier] = $relatedNodes;
        return $this->firstlevelCache[$assetIdentifier];
    }

    /**
     * Returns all nodes that use the asset in a node property.
     *
     * @param AssetInterface $asset
     * @return array
     */
    public function getRelatedNodes(AssetInterface $asset)
    {
        $relationMap = [];
        $relationMap[TypeHandling::getTypeForValue($asset)] = [$this->persistenceManager->getIdentifierByObject($asset)];

        if ($asset instanceof Image) {
            foreach ($asset->getVariants() as $variant) {
                $type = TypeHandling::getTypeForValue($variant);
                if (!isset($relationMap[$type])) {
                    $relationMap[$type] = [];
                }
                $relationMap[$type][] = $this->persistenceManager->getIdentifierByObject($variant);
            }
        }

        $allRelatedNodeDatas = $this->nodeDataRepository->findNodesByPathPrefixAndRelatedEntities(SiteService::SITES_ROOT_PATH, $relationMap);

        return array_filter($allRelatedNodeDatas, function (NodeData $relatedNodeData) {
            return !$relatedNodeData->isInternal();
        });
    }
}
