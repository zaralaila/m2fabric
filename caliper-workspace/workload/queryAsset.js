'use strict';

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');

class QueryAssetWorkload extends WorkloadModuleBase {
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
        const assetId = `asset_w${this.workerIndex}_1_${Date.now()}`;
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

function createWorkloadModule() {
    return new QueryAssetWorkload();
}

module.exports.createWorkloadModule = createWorkloadModule;
