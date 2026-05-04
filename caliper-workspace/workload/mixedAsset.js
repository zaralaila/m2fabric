'use strict';

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');

class MixedAssetWorkload extends WorkloadModuleBase {
    constructor() {
        super();
        this.txIndex = 0;
        this.seedAssets = [];
        this.initId = Date.now();
    }

    async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
        await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);
        this.workerIndex = workerIndex;
        this.contractId = roundArguments.contractId;

        console.log(`Worker ${workerIndex}: pre-creating seed assets`);
        for (let i = 0; i < 100; i++) {
            const assetId = `seed_${this.initId}_w${workerIndex}_${i}`;
            const request = {
                contractId: this.contractId,
                contractFunction: 'CreateAsset',
                invokerIdentity: 'org1caliper',
                contractArguments: [assetId, 'green', '5', 'Zara', '50'],
                readOnly: false
            };
            try {
                await this.sutAdapter.sendRequests(request);
            } catch (err) {
                // seed already exists from a previous round, that is fine
            }
            // Always add to seed list regardless — asset exists on ledger
            this.seedAssets.push(assetId);
        }
        console.log(`Worker ${workerIndex}: ${this.seedAssets.length} seed assets ready`);
    }

    async submitTransaction() {
        this.txIndex++;
        const isWrite = Math.random() < 0.7;

        if (isWrite) {
            // 70% path — create a new unique asset
            const assetId = `asset_${this.initId}_w${this.workerIndex}_${this.txIndex}`;
            const request = {
                contractId: this.contractId,
                contractFunction: 'CreateAsset',
                invokerIdentity: 'org1caliper',
                contractArguments: [assetId, 'blue', '10', 'Zara', '100'],
                readOnly: false
            };
            await this.sutAdapter.sendRequests(request);
        } else {
            // 30% path — read a seed asset that is guaranteed to exist
            const randomIndex = Math.floor(Math.random() * this.seedAssets.length);
            const assetId = this.seedAssets[randomIndex];
            const request = {
                contractId: this.contractId,
                contractFunction: 'ReadAsset',
                invokerIdentity: 'org1caliper',
                contractArguments: [assetId],
                readOnly: true
            };
            await this.sutAdapter.sendRequests(request);
        }
    }
}

function createWorkloadModule() {
    return new MixedAssetWorkload();
}

module.exports.createWorkloadModule = createWorkloadModule;
