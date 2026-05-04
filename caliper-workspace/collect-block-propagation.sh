#!/bin/bash
LABEL=${1:-"unlabelled"}
PROM="http://localhost:9090/api/v1/query?query="
OUT="$HOME/m2fabric/caliper-workspace/block-propagation.csv"
TS=$(date '+%Y-%m-%d %H:%M:%S')

if [ ! -f "$OUT" ]; then
    echo "timestamp,label,metric,value" >> "$OUT"
fi

pquery() {
    curl -sg "${PROM}$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$1")" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); r=d['data']['result']; print(r[0]['value'][1] if r else 'N/A')"
}

P1_HEIGHT=$(pquery "ledger_blockchain_height{job=\"fabric-peer-org1\",channel=\"mychannel\"}")
P2_HEIGHT=$(pquery "ledger_blockchain_height{job=\"fabric-peer-org2\",channel=\"mychannel\"}")
P1_COUNT=$(pquery "ledger_block_processing_time_count{job=\"fabric-peer-org1\",channel=\"mychannel\"}")
P2_COUNT=$(pquery "ledger_block_processing_time_count{job=\"fabric-peer-org2\",channel=\"mychannel\"}")
P1_PROC=$(pquery "rate(ledger_block_processing_time_sum{job=\"fabric-peer-org1\",channel=\"mychannel\"}[30m])/rate(ledger_block_processing_time_count{job=\"fabric-peer-org1\",channel=\"mychannel\"}[30m])")
P2_PROC=$(pquery "rate(ledger_block_processing_time_sum{job=\"fabric-peer-org2\",channel=\"mychannel\"}[30m])/rate(ledger_block_processing_time_count{job=\"fabric-peer-org2\",channel=\"mychannel\"}[30m])")
P1_BPS=$(pquery "rate(ledger_block_processing_time_count{job=\"fabric-peer-org1\",channel=\"mychannel\"}[30m])")
P2_BPS=$(pquery "rate(ledger_block_processing_time_count{job=\"fabric-peer-org2\",channel=\"mychannel\"}[30m])")

echo "$TS,$LABEL,peer1_block_height,${P1_HEIGHT:-N/A}" >> "$OUT"
echo "$TS,$LABEL,peer2_block_height,${P2_HEIGHT:-N/A}" >> "$OUT"
echo "$TS,$LABEL,peer1_block_count,${P1_COUNT:-N/A}" >> "$OUT"
echo "$TS,$LABEL,peer2_block_count,${P2_COUNT:-N/A}" >> "$OUT"
echo "$TS,$LABEL,peer1_avg_block_proc_s,${P1_PROC:-N/A}" >> "$OUT"
echo "$TS,$LABEL,peer2_avg_block_proc_s,${P2_PROC:-N/A}" >> "$OUT"
echo "$TS,$LABEL,peer1_blocks_per_sec,${P1_BPS:-N/A}" >> "$OUT"
echo "$TS,$LABEL,peer2_blocks_per_sec,${P2_BPS:-N/A}" >> "$OUT"

echo "Block propagation metrics recorded:"
echo "  Label:               $LABEL"
echo "  Peer1 block height:  ${P1_HEIGHT:-N/A}"
echo "  Peer2 block height:  ${P2_HEIGHT:-N/A}"
echo "  Peer1 block count:   ${P1_COUNT:-N/A}"
echo "  Peer2 block count:   ${P2_COUNT:-N/A}"
echo "  Peer1 avg proc time: ${P1_PROC:-N/A} s/block"
echo "  Peer2 avg proc time: ${P2_PROC:-N/A} s/block"
echo "  Peer1 blocks/sec:    ${P1_BPS:-N/A}"
echo "  Peer2 blocks/sec:    ${P2_BPS:-N/A}"
echo "  Saved to: $OUT"
