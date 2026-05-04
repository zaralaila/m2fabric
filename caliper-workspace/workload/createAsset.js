'use strict';

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');

class CreateAssetWorkload extends WorkloadModuleBase {
    constructor() {
        super();
        this.txIndex = 0;
    }

    async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
        await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);
        this.workerIndex = workerIndex;
        this.contractId = roundArguments.contractId;
    }

    async submitTransaction() {
        this.txIndex++;
        const assetId = `asset_w${this.workerIndex}_${this.txIndex}_${Date.now()}`;
        const request = {
            contractId: this.contractId,
            contractFunction: 'CreateAsset',
            invokerIdentity: 'org1caliper',
            contractArguments: [assetId, 'blue', '10', 'Zara', '100'],
            readOnly: false
        };
        await this.sutAdapter.sendRequests(request);
    }
}

function createWorkloadModule() {
    return new CreateAssetWorkload();
}

module.exports.createWorkloadModule = createWorkloadModule;
