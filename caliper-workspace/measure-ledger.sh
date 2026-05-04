#!/bin/bash
# Usage: ./measure-ledger.sh <label>
# Records ledger storage size for both peers after a benchmark run.

LABEL=${1:-"unlabelled"}
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
OUTPUT_FILE="$HOME/m2fabric/caliper-workspace/ledger-measurements.csv"

# Write header if file does not exist
if [ ! -f "$OUTPUT_FILE" ]; then
    echo "timestamp,label,peer1_ledger_bytes,peer2_ledger_bytes,total_bytes" >> "$OUTPUT_FILE"
fi

# Get ledger sizes from Docker containers
PEER1=$(docker exec peer0.org1.example.com du -sb /var/hyperledger/production/ledgersData 2>/dev/null | awk '{print $1}')
PEER2=$(docker exec peer0.org2.example.com du -sb /var/hyperledger/production/ledgersData 2>/dev/null | awk '{print $1}')

if [ -z "$PEER1" ] || [ -z "$PEER2" ]; then
    echo "ERROR: Could not reach peer containers. Is the network running?"
    exit 1
fi

TOTAL=$((PEER1 + PEER2))

echo "$TIMESTAMP,$LABEL,$PEER1,$PEER2,$TOTAL" >> "$OUTPUT_FILE"
echo "Ledger measurement recorded:"
echo "  Label:   $LABEL"
echo "  Peer1:   $PEER1 bytes ($(echo "scale=2; $PEER1/1024/1024" | bc) MB)"
echo "  Peer2:   $PEER2 bytes ($(echo "scale=2; $PEER2/1024/1024" | bc) MB)"
echo "  Total:   $TOTAL bytes ($(echo "scale=2; $TOTAL/1024/1024" | bc) MB)"
echo "  Saved to: $OUTPUT_FILE"
