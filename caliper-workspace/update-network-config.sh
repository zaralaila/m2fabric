#!/bin/bash
# Updates Caliper network config after ./network.sh up createChannel -ca
# PQC implementation: keys are always stored as key.pem (not SKI-named)
# Nothing to update for key paths — key.pem is fixed.
# This script now just verifies the key files exist.

BASE=~/go/src/github.com/zaralaila/m2fabric/fabric-samples/test-network/organizations/peerOrganizations
for org in org1 org2; do
    KEY="${BASE}/${org}.example.com/users/Admin@${org}.example.com/msp/keystore/key.pem"
    if [ -f "$KEY" ]; then
        echo "✓ ${org} key.pem exists"
    else
        echo "✗ ${org} key.pem MISSING — did you run network.sh up -ca?"
    fi
done
echo "Network config needs no path updates (PQC uses fixed key.pem)"
