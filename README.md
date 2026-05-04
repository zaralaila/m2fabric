# M²Fabric

**A post-quantum cryptographic multilayer architecture for Hyperledger Fabric.**

M²Fabric is a complete runtime-level integration of NIST-standardised post-quantum cryptographic algorithms across all four cryptographic layers of Hyperledger Fabric v2.5:

| Layer | What it secures | M²Fabric algorithm | Standard |
|---|---|---|---|
| BCCSP | Transaction signing, block signing, gossip | FN-DSA-512 / ML-DSA-44 / ML-DSA-65 | FIPS 204, FIPS 206 |
| Fabric CA | Certificate issuance | FN-DSA-512 leaf keys (dual-CA design) | FIPS 206 |
| MSP | Identity validation, NodeOU | `buildPQCChain()` validator | — |
| TLS | Inter-node key exchange | Hybrid X25519 + ML-KEM-768 | FIPS 203 |

This repository accompanies the PhD thesis *"M²Fabric: A Post-Quantum Cryptographic Multilayer Architecture for Hyperledger Fabric"* (Universiti Brunei Darussalam, 2026).

## Background

Hyperledger Fabric v2.5 relies uniformly on ECDSA P-256 and ECDH P-256, both of which collapse under Shor's algorithm on a cryptographically-relevant quantum computer. Because Fabric's ledger is append-only and immutable, every historical transaction signature, certificate, and TLS handshake is preserved indefinitely as a harvest-now-decrypt-later target — and no key rotation can retroactively remove the vulnerability.

M²Fabric replaces the quantum-vulnerable primitives across every cryptographic layer with FIPS-standardised post-quantum algorithms in pure Go (no CGo dependency).

See chapter 4 of the thesis for the full quantum threat model and chapter 5 for the architecture.

## Repository structure

```
.
├── pqc-bccsp/           # The post-quantum BCCSP plugin (FN-DSA, ML-DSA, ML-KEM)
├── fabric-source/       # Hyperledger Fabric 2.5.x fork with PQC integration
├── fabric-ca/           # Hyperledger Fabric CA 1.5.x fork with PQC issuance + buildPQCChain
├── fabric-samples/      # test-network with PQC-aware registerEnroll.sh + dual-CA setup
├── caliper-workspace/   # Caliper benchmarks (workload, network config, baseline yamls)
├── prometheus/          # Prometheus scrape config for runtime metrics
├── Dockerfile.pqc-{ca,peer,orderer}   # Overlay PQC binaries onto stock hyperledger:* images
└── install-fabric.sh    # Fabric/CA version installer (2.5.15 / 1.5.17)
```

The `fabric-source/` and `fabric-ca/` directories are forks of upstream Hyperledger projects (Apache 2.0) carrying the PQC integration patches. `fabric-samples/` is similarly a fork carrying the `caliper-ca` dual-CA setup and PQC-aware `registerEnroll.sh`.

## Prerequisites

- **macOS or Linux**, x86_64
- **Go 1.26+** (for building host binaries)
- **Docker** + Docker Compose
- **Node.js 18+** and **npm** (for Caliper)
- **OpenSSL** (for cert inspection / TLS handshake verification)

## Setup

### 1. Clone

```bash
mkdir -p ~/go/src/github.com/zaralaila
cd ~/go/src/github.com/zaralaila
git clone https://github.com/zaralaila/m2fabric.git
cd m2fabric
```

### 2. Build the Linux binaries (used inside Docker images)

```bash
# Cross-compile the PQC peer + orderer for linux/amd64
(cd fabric-source && GOOS=linux GOARCH=amd64 make peer FABRIC_VER=latest)
cp fabric-source/build/bin/peer pqc-peer-linux

(cd fabric-source && GOOS=linux GOARCH=amd64 make orderer FABRIC_VER=latest)
cp fabric-source/build/bin/orderer pqc-orderer-linux

# Build the PQC fabric-ca server + client for linux/amd64
(cd fabric-ca && GOOS=linux GOARCH=amd64 make fabric-ca-server BASE_VERSION=1.5.12)
(cd fabric-ca && GOOS=linux GOARCH=amd64 make fabric-ca-client BASE_VERSION=1.5.12)
cp fabric-ca/bin/fabric-ca-server fabric-ca/fabric-ca-server-linux
cp fabric-ca/bin/fabric-ca-client fabric-ca/fabric-ca-client-linux
```

### 3. Build the host binaries (used by `network.sh`, Caliper, etc.)

```bash
# Install the upstream binaries to fabric-samples/bin/
./install-fabric.sh -f 2.5.15 -c 1.5.17 binary

# Build the host PQC peer and fabric-ca-client with version strings
# matching the docker images (so network.sh's version-check warnings stay quiet)
(cd fabric-source && make peer FABRIC_VER=latest)
(cd fabric-ca     && make fabric-ca-client BASE_VERSION=1.5.12)

# Replace stock binaries with PQC builds; keep stock as backup
mv fabric-samples/bin/peer              fabric-samples/bin/peer.stock
mv fabric-samples/bin/fabric-ca-client  fabric-samples/bin/fabric-ca-client.stock
cp fabric-source/build/bin/peer         fabric-samples/bin/
cp fabric-ca/bin/fabric-ca-client       fabric-samples/bin/
```

> The host stock binaries from `install-fabric.sh` do not understand `--csr.keyrequest.algo fndsa512` and cannot load PQC keys, so the swap is required.

### 4. Build the Docker images

```bash
docker build -f Dockerfile.pqc-peer    -t hyperledger/fabric-peer:pqc    .
docker build -f Dockerfile.pqc-orderer -t hyperledger/fabric-orderer:pqc .
docker build -f Dockerfile.pqc-ca      -t hyperledger/fabric-ca:pqc      fabric-ca/
```

> Note the **build context for the CA image is `fabric-ca/`**, not the project root, because the linux binaries it copies live there.

Verify the PQC binaries are in the images:

```bash
docker run --rm --entrypoint sha1sum hyperledger/fabric-peer:pqc /usr/local/bin/peer
docker run --rm --entrypoint sha1sum hyperledger/fabric-orderer:pqc /usr/local/bin/orderer
```

### 5. Install Caliper

```bash
(cd caliper-workspace && npm install)
```

## Running the test network

```bash
cd fabric-samples/test-network

./network.sh up -ca           # Start CAs, peers, orderer (all PQC images)
./network.sh createChannel    # Create mychannel, both peers join
./network.sh deployCC -ccn basic -ccp ../asset-transfer-basic/chaincode-go -ccl go
```

Tear down when done:

```bash
./network.sh down
```

## Running benchmarks

```bash
cd caliper-workspace

# Smoke test (~40s, sanity check)
./node_modules/.bin/caliper launch manager \
  --caliper-workspace . \
  --caliper-networkconfig networks/fabric-network.yaml \
  --caliper-benchconfig   benchmarks/smoke-test.yaml \
  --caliper-flow-only-test

# Full baseline sweep (~26 min)
./node_modules/.bin/caliper launch manager \
  --caliper-workspace . \
  --caliper-networkconfig networks/fabric-network.yaml \
  --caliper-benchconfig   benchmarks/baseline.yaml \
  --caliper-flow-only-test

# Reports land in caliper-workspace/report.html (overwritten each run)
```

To switch signing algorithm, edit `--csr.keyrequest.algo` in [organizations/fabric-ca/registerEnroll.sh](fabric-samples/test-network/organizations/fabric-ca/registerEnroll.sh) (`mldsa44`, `mldsa65`, or `fndsa512`), then `network.sh down && up -ca && createChannel && deployCC`.

## Verifying the deployment is end-to-end PQC

```bash
# Check a peer's signing cert public-key OID (1.3.9999.3.6 == FN-DSA-512)
openssl x509 -in fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/msp/signcerts/cert.pem -text -noout | grep "Public Key Algorithm"

# Verify hybrid TLS is negotiated on the orderer
openssl s_client -connect localhost:7050 -groups 'X25519MLKEM768' </dev/null 2>&1 | grep "Negotiated TLS"
# Expected: Negotiated TLS1.3 group: X25519MLKEM768

# Inspect a block — orderer signature should be ~700+ bytes (FN-DSA), not ~70 (ECDSA)
peer channel fetch newest /tmp/block.bin -c mychannel \
  -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls \
  --cafile fabric-samples/test-network/organizations/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem
configtxlator proto_decode --type common.Block --input /tmp/block.bin --output /tmp/block.json
```

## Architecture: dual-CA design

M²Fabric uses a **dual-CA architecture** (thesis §5.7.3):

- **PQC issuing CA** (`localhost-7054-ca-org1`) issues peer / admin / orderer identities with FN-DSA-512 keys. The issuing CA's own root key is ECDSA P-256 — this is a partial-migration vulnerability documented as TS1 in chapter 4.4.2.
- **`caliper-ca`** is a separate ECDSA root that issues the `caliper@orgN.example.com` client identity. This exists because Node.js's OpenSSL cannot decode FN-DSA private keys, so Caliper needs a classical client identity to drive load. Server-side endorsement and block signing remain post-quantum.

NodeOU pinning enforces:
- `client` identities must come from `caliper-ca-orgN.pem`
- `peer` / `admin` / `orderer` identities must come from the PQC CA

See `organizations/peerOrganizations/orgN.example.com/msp/config.yaml` for the OU pinning.

## Algorithms used

| Use | Algorithm | Standard | Library |
|---|---|---|---|
| Digital signature (BCCSP) | ML-DSA-44, ML-DSA-65 | FIPS 204 | [`circl/sign/mldsa`](https://github.com/cloudflare/circl) |
| Digital signature (BCCSP) | FN-DSA-512 (FALCON-512) | FIPS 206 | [`go-fn-dsa`](https://github.com/pornin/go-fn-dsa) |
| Key encapsulation (TLS) | ML-KEM-768 (hybrid w/ X25519) | FIPS 203 | Go stdlib `crypto/mlkem` (1.23+) |

All implementations are pure Go — no CGo, no liboqs runtime dependency.

## Common gotchas

| Symptom | Cause | Fix |
|---|---|---|
| `Invalid algorithm: fndsa512` during enrollment | Stock fabric-ca-client on PATH | Build & swap as in step 3 above |
| `Certificate's public key type not recognized. Supported keys: [ECDSA, RSA]` | Stock peer on PATH | Build & swap as in step 3 above |
| `error:1E08010C:DECODER routines::unsupported` from Caliper | Caliper config points at PQC user key | Use the `caliper@orgN.example.com` user, not `User1@` |
| `access denied: certifiersIdentifier does not match` | Wrong CA in fabric-network.yaml | Same as above — `caliper@` is the only valid client identity |
| `Local fabric binaries and docker images are out of sync` | Host binaries built with default version strings | Rebuild with `make peer FABRIC_VER=latest` and `make fabric-ca-client BASE_VERSION=1.5.12` |
| Dockerfile.pqc-ca COPY fails with "not found" | Wrong build context | Use `fabric-ca/` as the build context, not `.` |

## Citation

If you use M²Fabric in academic work, please cite:

```bibtex
@phdthesis{cheong2026m2fabric,
  author  = {Cheong, Zara Laila},
  title   = {{M\textsuperscript{2}Fabric}: A Post-Quantum Cryptographic Multilayer Architecture for Hyperledger Fabric},
  school  = {Universiti Brunei Darussalam},
  year    = {2026},
  type    = {{PhD} thesis},
  address = {School of Digital Science}
}
```

## Acknowledgements

This work builds on the open-source contributions of:

- The **Hyperledger Fabric** maintainers (Apache 2.0)
- **Cloudflare CIRCL** — ML-DSA reference implementation
- **Thomas Pornin's `go-fn-dsa`** — FN-DSA reference implementation
- The **Open Quantum Safe** project — algorithm test vectors and ACVP data
- The **Go team** for `crypto/mlkem` in the standard library

## License

Apache License 2.0. See [LICENSE](LICENSE).

The vendored `fabric-source/`, `fabric-ca/`, and `fabric-samples/` directories are forks of upstream Hyperledger projects, originally released under Apache 2.0. The PQC integration patches and the original work in `pqc-bccsp/`, `caliper-workspace/`, and the Dockerfiles are licensed under the same terms.
