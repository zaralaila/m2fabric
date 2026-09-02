# M²Fabric

**A post-quantum cryptographic multilayer architecture for Hyperledger Fabric.**

M²Fabric is a complete runtime-level integration of NIST-standardised post-quantum cryptographic algorithms across all four cryptographic layers of Hyperledger Fabric v2.5.12 (with Fabric CA v1.5.12):

| Layer | What it secures | M²Fabric algorithm | Standard |
|---|---|---|---|
| BCCSP | Transaction signing, block signing, gossip | FN-DSA-512 / ML-DSA-44 / ML-DSA-65 | FIPS 204, FIPS 206 |
| Fabric CA | Certificate issuance | FN-DSA-512 leaf keys (dual-CA design) | FIPS 206 |
| MSP | Identity validation, NodeOU | `buildPQCChain()` — OID-dispatched signature verification, validity period, KeyUsage `keyCertSign`, AKID/SKID match | — |
| TLS | Inter-node key exchange | Hybrid X25519 + ML-KEM-768 (`X25519MLKEM768`) | FIPS 203 |

TLS *certificates* (and the Caliper client identity) remain ECDSA P-256 — only the TLS key exchange is post-quantum. See [Architecture](#architecture-ca-topology-and-trust-boundaries) for the exact trust boundaries.

This repository accompanies the PhD thesis *"M²Fabric: A Post-Quantum Cryptographic Multilayer Architecture for Hyperledger Fabric"* (Universiti Brunei Darussalam, 2026).

## Background

Hyperledger Fabric v2.5 relies uniformly on ECDSA P-256 and ECDH P-256, both of which collapse under Shor's algorithm on a cryptographically-relevant quantum computer. Because Fabric's ledger is append-only and immutable, every historical transaction signature, certificate, and TLS handshake is preserved indefinitely as a harvest-now-decrypt-later target — and no key rotation can retroactively remove the vulnerability.

M²Fabric replaces the quantum-vulnerable primitives across every cryptographic layer with FIPS-standardised post-quantum algorithms in pure Go (no CGo dependency).

See chapter 4 of the thesis for the full quantum threat model and chapter 5 for the architecture.

## Repository structure

```
.
├── pqc-bccsp/           # Standalone PQC crypto module (ML-DSA-44/65, FN-DSA-512): keygen, sign, verify
├── fabric-source/       # Hyperledger Fabric 2.5.12 fork: PQC BCCSP factory, buildPQCChain MSP validator, hybrid TLS
├── fabric-ca/           # Hyperledger Fabric CA 1.5.12 fork: PQC key generation, CSR handling, certificate issuance
├── fabric-samples/      # test-network with PQC-aware registerEnroll.sh + multi-CA setup
├── caliper-workspace/   # Caliper benchmarks (workloads, network config, smoke/baseline/baseline-mixed yamls)
├── results/             # Caliper HTML reports (ECDSA baseline + 3 PQC algos × write/mixed × 3 runs × 3 phases)
│                        # plus block-propagation.csv and ledger-measurements.csv
├── prometheus/          # Prometheus scrape config for peer/orderer runtime metrics
├── Dockerfile.pqc-{ca,peer,orderer}   # Overlay PQC binaries onto stock hyperledger:* 2.5.12 / 1.5.12 images
└── install-fabric.sh    # Upstream installer for auxiliary host tools (fetches 2.5.15 / 1.5.17)
```

The `fabric-source/` and `fabric-ca/` directories are forks of upstream Hyperledger projects (Apache 2.0) carrying the PQC integration patches. `fabric-samples/` is similarly a fork carrying the multi-CA setup and PQC-aware `registerEnroll.sh`. Both forks consume `pqc-bccsp/` through a `replace github.com/zaralaila/pqc-bccsp => ../pqc-bccsp` directive in their `go.mod`, so the directory layout of this repository must be preserved for the builds to work.

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

./network.sh up -ca           # Start CAs, peers, orderer (PQC images)
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

# Full write-only baseline sweep (13 rounds, 25→1000 TPS, 120 s each)
./node_modules/.bin/caliper launch manager \
  --caliper-workspace . \
  --caliper-networkconfig networks/fabric-network.yaml \
  --caliper-benchconfig   benchmarks/baseline.yaml \
  --caliper-flow-only-test

# Mixed 70% create / 30% query sweep (same 13-round ladder)
./node_modules/.bin/caliper launch manager \
  --caliper-workspace . \
  --caliper-networkconfig networks/fabric-network.yaml \
  --caliper-benchconfig   benchmarks/baseline-mixed.yaml \
  --caliper-flow-only-test

# Reports land in caliper-workspace/report.html (overwritten each run)
```

> The `test.name` embedded in every generated report is `fabric-baseline-ecdsa[-mixed]` regardless of which algorithm the network was built with — the algorithm is selected at network-build time, not in the benchmark yaml. Rename the report after each run (as done in `results/`).

To switch signing algorithm (`mldsa44`, `mldsa65`, or `fndsa512`), edit:

1. `--csr.keyrequest.algo` in [organizations/fabric-ca/registerEnroll.sh](fabric-samples/test-network/organizations/fabric-ca/registerEnroll.sh) — the algorithm of all issued identity keys, and
2. `BCCSP.PQC.Algorithm` in [compose/docker/peercfg/core.yaml](fabric-samples/test-network/compose/docker/peercfg/core.yaml) — the peer's default algorithm (verification is OID-dispatched per certificate, but keep the two in sync),

then `network.sh down && up -ca && createChannel && deployCC`.

## Benchmark results

`results/` contains the raw measurement data behind the thesis evaluation chapters:

- 61 Caliper HTML reports: `report[-phaseN]-{ecdsa,mldsa44,mldsa65,fndsa512}-{write,mixed}-run{1..3}.html` (phase 1 unprefixed; phases 2–3 cover the PQC algorithms)
- `block-propagation.csv` — Prometheus-derived block propagation metrics per run (phase 1)
- `ledger-measurements.csv` — per-peer ledger size in bytes per run (phase 1)

## Running the unit tests

The MSP `buildPQCChain` validator has 9 test functions (17 tests counting per-algorithm subtests) covering valid chains, tampered signatures, unknown issuers, expired and not-yet-valid certs, unconfigured roots, the legacy SHA-256-pre-hash fallback for pre-fix certificates, and `signatureAlgorithm`-OID stamping by the live cert generator — the signature-path tests each run across ML-DSA-44, ML-DSA-65, and FN-DSA-512:

```bash
(cd fabric-source && go test -count=1 -v -run TestBuildPQCChain ./msp/)
```

The `pqc-bccsp` module carries its own round-trip, tamper-rejection, and FIPS key/signature-size tests:

```bash
(cd pqc-bccsp && go test -count=1 -v ./pqc/)
```

## Verifying the deployment is end-to-end PQC

```bash
# Check a peer's signing cert: the public-key OID should be a PQC OID
# (1.3.9999.3.6 == FN-DSA-512, 2.16.840.1.101.3.4.3.17 == ML-DSA-44,
#  2.16.840.1.101.3.4.3.18 == ML-DSA-65).
# The signature-algorithm OID depends on the issuing CA's own key:
# ecdsa-with-SHA256 under the default ECDSA root (the TS1 partial-migration
# boundary below), or the same PQC OID when the CA is given a PQC root key.
CERT=fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/msp/signcerts/cert.pem
openssl x509 -in "$CERT" -text -noout | grep -E "Signature Algorithm|Public Key Algorithm"

# Verify hybrid TLS is negotiated on the orderer
openssl s_client -connect localhost:7050 -groups 'X25519MLKEM768' </dev/null 2>&1 | grep "Negotiated TLS"
# Expected: Negotiated TLS1.3 group: X25519MLKEM768

# Inspect a block — orderer signature should be ~700+ bytes (FN-DSA), not ~70 (ECDSA)
peer channel fetch newest /tmp/block.bin -c mychannel \
  -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls \
  --cafile fabric-samples/test-network/organizations/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem
configtxlator proto_decode --type common.Block --input /tmp/block.bin --output /tmp/block.json
```

## Architecture: CA topology and trust boundaries

On the identity plane, M²Fabric uses a **dual-CA architecture** (thesis §5.7.3), with a third, local CA for TLS:

- **PQC issuing CA** (`localhost-7054-ca-org1`, the patched `fabric-ca:pqc` server) issues peer / admin / orderer / user identities with FN-DSA-512 keys via `--csr.keyrequest.algo fndsa512`. The issuing CA's own root key is ECDSA P-256 — this is a partial-migration vulnerability documented as TS1 in chapter 4.4.2, and it is why the leaf certificates' outer `signatureAlgorithm` is `ecdsa-with-SHA256` while their subject keys are FN-DSA-512.
- **`caliper-ca`** is a separate ECDSA root (openssl-generated in `registerEnroll.sh`) that issues the `caliper@orgN.example.com` client identity. This exists because Node.js's OpenSSL cannot decode FN-DSA private keys, so Caliper needs a classical client identity to drive load. Server-side endorsement and block signing remain post-quantum.
- **TLS CA**: each org additionally gets an openssl-generated ECDSA P-256 TLS root (`tls-ca-cert.pem`) that issues the node TLS server certificates, replacing the stock `--enrollment.profile tls` enrollment. TLS *authentication* is therefore classical; post-quantum protection of the transport comes from the hybrid `X25519MLKEM768` key exchange configured in `fabric-source/internal/pkg/comm/`.

NodeOU pinning enforces:
- `client` identities must come from `caliper-ca-orgN.pem`
- `peer` / `admin` / `orderer` identities must come from the PQC CA

See `organizations/peerOrganizations/orgN.example.com/msp/config.yaml` for the OU pinning.

In summary, the quantum-safe boundary covers transaction/endorsement/block signatures (PQC leaf keys, verified by `buildPQCChain` and the PQC BCCSP) and the TLS key exchange (hybrid ML-KEM-768); the CA root signatures, TLS certificates, and the Caliper client identity remain classical ECDSA P-256 by design and are documented as such in the thesis threat model.

## Algorithms used

| Use | Algorithm | Standard | Library |
|---|---|---|---|
| Digital signature (BCCSP) | ML-DSA-44, ML-DSA-65 | FIPS 204 | [`circl/sign/mldsa`](https://github.com/cloudflare/circl) |
| Digital signature (BCCSP) | FN-DSA-512 (FALCON-512) | FIPS 206 | [`go-fn-dsa`](https://github.com/pornin/go-fn-dsa) |
| Key encapsulation (TLS) | ML-KEM-768 (hybrid w/ X25519, `X25519MLKEM768`) | FIPS 203 | Go stdlib `crypto/tls` / `crypto/mlkem` (Go 1.24+; built with 1.26) |

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
| Peers come up on stock images | Base `compose-test-net.yaml` references `fabric-peer:latest`; the `:pqc` tag is applied by the `compose/docker/docker-compose-test-net.yaml` override that `network.sh` layers on top | Always start via `network.sh` (or tag/retag so both files agree); the BFT compose variants are not PQC-enabled |

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
