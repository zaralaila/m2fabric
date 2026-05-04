#!/usr/bin/env bash

# ---------------------------------------------------------------------------
# TLS helper functions — generate ECDSA TLS certs (separate from PQC MSP CAs)
# ---------------------------------------------------------------------------

# Create a per-org ECDSA root CA used exclusively for TLS certificates.
# Args: CA_DIR (directory to write tls-ca-key.pem and tls-ca-cert.pem)
#        ORG_NAME (e.g. "org1.example.com", used in Subject)
function createTLSCA() {
  local CA_DIR=$1
  local ORG_NAME=${2:-example.com}
  infoln "Generating ECDSA TLS CA for ${ORG_NAME}"
  openssl ecparam -genkey -name prime256v1 -noout -out "${CA_DIR}/tls-ca-key.pem" 2>/dev/null
  openssl req -new -x509 -key "${CA_DIR}/tls-ca-key.pem" \
    -out "${CA_DIR}/tls-ca-cert.pem" -days 3650 \
    -subj "/CN=tls-ca.${ORG_NAME}/O=${ORG_NAME}" 2>/dev/null
}

# Generate an ECDSA TLS server certificate signed by the org's ECDSA TLS CA.
# Args: CA_DIR   — contains tls-ca-key.pem / tls-ca-cert.pem
#       OUT_DIR  — output directory (server.crt, server.key, ca.crt written here)
#       CN       — Common Name for the server cert
#       SANS...  — one or more DNS SANs (space-separated)
function generateTLSCert() {
  local CA_DIR=$1
  local OUT_DIR=$2
  local CN=$3
  shift 3
  local SANS="$*"

  mkdir -p "${OUT_DIR}"

  # Generate ECDSA P-256 server key
  openssl ecparam -genkey -name prime256v1 -noout -out "${OUT_DIR}/server.key" 2>/dev/null

  # Build SAN extension string
  local SAN_EXT="subjectAltName="
  local first=true
  for h in $SANS; do
    $first || SAN_EXT="${SAN_EXT},"
    SAN_EXT="${SAN_EXT}DNS:${h}"
    first=false
  done

  # Create CSR
  openssl req -new -key "${OUT_DIR}/server.key" -out "${OUT_DIR}/server.csr" \
    -subj "/CN=${CN}" 2>/dev/null

  # Sign with TLS CA
  openssl x509 -req -in "${OUT_DIR}/server.csr" \
    -CA "${CA_DIR}/tls-ca-cert.pem" -CAkey "${CA_DIR}/tls-ca-key.pem" \
    -CAcreateserial -out "${OUT_DIR}/server.crt" -days 3650 \
    -extfile <(printf '%s\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth,clientAuth' "$SAN_EXT") 2>/dev/null

  # Copy TLS CA cert alongside the server cert
  cp "${CA_DIR}/tls-ca-cert.pem" "${OUT_DIR}/ca.crt"

  # Cleanup temp files
  rm -f "${OUT_DIR}/server.csr"
}

# Create a per-org ECDSA root CA used for Caliper client identities.
# Args: CA_DIR  — directory to write caliper-ca-key.pem and caliper-ca-cert.pem
#       ORG_NAME — e.g. "org1.example.com"
function createCaliperCA() {
  local CA_DIR=$1
  local ORG_NAME=${2:-example.com}
  infoln "Generating ECDSA Caliper Client CA for ${ORG_NAME}"
  openssl ecparam -genkey -name prime256v1 -noout -out "${CA_DIR}/caliper-ca-key.pem" 2>/dev/null
  openssl req -new -x509 -key "${CA_DIR}/caliper-ca-key.pem" \
    -out "${CA_DIR}/caliper-ca-cert.pem" -days 3650 \
    -subj "/CN=caliper-ca.${ORG_NAME}/O=${ORG_NAME}" 2>/dev/null
}

# Generate an ECDSA P-256 Caliper client identity signed by the caliper CA.
# Node.js createPrivateKey() can load EC keys; ML-DSA keys it cannot.
# Args: CA_DIR  — contains caliper-ca-key.pem / caliper-ca-cert.pem
#       OUT_DIR — directory for the identity (msp/keystore and msp/signcerts created here)
#       CN      — Common Name for the client cert  (e.g. caliper@org1.example.com)
function generateCaliperCert() {
  local CA_DIR=$1
  local OUT_DIR=$2
  local CN=$3

  mkdir -p "${OUT_DIR}/msp/keystore" "${OUT_DIR}/msp/signcerts"

  # ECDSA P-256 signing key (Node.js-compatible)
  openssl ecparam -genkey -name prime256v1 -noout \
    -out "${OUT_DIR}/msp/keystore/key.pem" 2>/dev/null

  # CSR — OU=client so NodeOUs assigns the 'client' role
  openssl req -new \
    -key "${OUT_DIR}/msp/keystore/key.pem" \
    -out "${OUT_DIR}/msp/keystore/csr.pem" \
    -subj "/CN=${CN}/OU=client" 2>/dev/null

  # Sign with the caliper CA
  openssl x509 -req \
    -in  "${OUT_DIR}/msp/keystore/csr.pem" \
    -CA  "${CA_DIR}/caliper-ca-cert.pem" \
    -CAkey "${CA_DIR}/caliper-ca-key.pem" \
    -CAcreateserial \
    -out "${OUT_DIR}/msp/signcerts/cert.pem" \
    -days 3650 \
    -extfile <(printf 'keyUsage=digitalSignature\nbasicConstraints=CA:FALSE') 2>/dev/null

  rm -f "${OUT_DIR}/msp/keystore/csr.pem"
}

# ---------------------------------------------------------------------------
# Org / Orderer creation functions
# ---------------------------------------------------------------------------

function createOrg1() {
  infoln "Enrolling the CA admin"
  mkdir -p organizations/peerOrganizations/org1.example.com/

  export FABRIC_CA_CLIENT_HOME=${PWD}/organizations/peerOrganizations/org1.example.com/

  set -x
  fabric-ca-client enroll -u https://admin:adminpw@localhost:7054 --caname ca-org1 --csr.keyrequest.algo fndsa512 --tls.certfiles "${PWD}/organizations/fabric-ca/org1/tls-cert.pem"
  { set +x; } 2>/dev/null

  # Generate ECDSA Caliper CA for org1 and add its cert to the MSP cacerts so that
  # the genesis block trusts it.  This must happen before config.yaml is written.
  createCaliperCA "${PWD}/organizations/fabric-ca/org1" "org1.example.com"
  cp "${PWD}/organizations/fabric-ca/org1/caliper-ca-cert.pem" \
     "${PWD}/organizations/peerOrganizations/org1.example.com/msp/cacerts/caliper-ca-org1.pem"

  # ClientOUIdentifier now references the ECDSA Caliper CA so that Caliper
  # client identities (ECDSA, OU=client) are recognized as Org1MSP.client.
  # Peer / admin / orderer identities are still PQC-signed and use their own
  # OU identifiers, both of which remain pointed at the PQC CA.
  echo 'NodeOUs:
  Enable: true
  ClientOUIdentifier:
    Certificate: cacerts/caliper-ca-org1.pem
    OrganizationalUnitIdentifier: client
  PeerOUIdentifier:
    Certificate: cacerts/localhost-7054-ca-org1.pem
    OrganizationalUnitIdentifier: peer
  AdminOUIdentifier:
    Certificate: cacerts/localhost-7054-ca-org1.pem
    OrganizationalUnitIdentifier: admin
  OrdererOUIdentifier:
    Certificate: cacerts/localhost-7054-ca-org1.pem
    OrganizationalUnitIdentifier: orderer' > "${PWD}/organizations/peerOrganizations/org1.example.com/msp/config.yaml"

  # Generate ECDSA TLS CA for org1
  createTLSCA "${PWD}/organizations/fabric-ca/org1" "org1.example.com"

  # Copy TLS CA cert to org-level tlscacerts directory (for channel MSP definition)
  mkdir -p "${PWD}/organizations/peerOrganizations/org1.example.com/msp/tlscacerts"
  cp "${PWD}/organizations/fabric-ca/org1/tls-ca-cert.pem" "${PWD}/organizations/peerOrganizations/org1.example.com/msp/tlscacerts/ca.crt"

  # Copy TLS CA cert to org-level /tlsca directory (for use by clients)
  mkdir -p "${PWD}/organizations/peerOrganizations/org1.example.com/tlsca"
  cp "${PWD}/organizations/fabric-ca/org1/tls-ca-cert.pem" "${PWD}/organizations/peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem"

  # Copy org1's PQC CA cert to org1's /ca directory (for use by clients)
  mkdir -p "${PWD}/organizations/peerOrganizations/org1.example.com/ca"
  cp "${PWD}/organizations/fabric-ca/org1/ca-cert.pem" "${PWD}/organizations/peerOrganizations/org1.example.com/ca/ca.org1.example.com-cert.pem"

  infoln "Registering peer0"
  set -x
  fabric-ca-client register --caname ca-org1 --id.name peer0 --id.secret peer0pw --id.type peer --tls.certfiles "${PWD}/organizations/fabric-ca/org1/tls-cert.pem"
  { set +x; } 2>/dev/null

  infoln "Registering user"
  set -x
  fabric-ca-client register --caname ca-org1 --id.name user1 --id.secret user1pw --id.type client --tls.certfiles "${PWD}/organizations/fabric-ca/org1/tls-cert.pem"
  { set +x; } 2>/dev/null

  infoln "Registering the org admin"
  set -x
  fabric-ca-client register --caname ca-org1 --id.name org1admin --id.secret org1adminpw --id.type admin --tls.certfiles "${PWD}/organizations/fabric-ca/org1/tls-cert.pem"
  { set +x; } 2>/dev/null

  infoln "Generating the peer0 msp"
  set -x
  fabric-ca-client enroll -u https://peer0:peer0pw@localhost:7054 --caname ca-org1 -M "${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/msp" --csr.keyrequest.algo fndsa512 --tls.certfiles "${PWD}/organizations/fabric-ca/org1/tls-cert.pem"
  { set +x; } 2>/dev/null

  cp "${PWD}/organizations/peerOrganizations/org1.example.com/msp/config.yaml" "${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/msp/config.yaml"
  cp "${PWD}/organizations/fabric-ca/org1/caliper-ca-cert.pem" "${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/msp/cacerts/caliper-ca-org1.pem"

  infoln "Generating the peer0-tls certificates (ECDSA, signed by TLS CA)"
  generateTLSCert \
    "${PWD}/organizations/fabric-ca/org1" \
    "${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls" \
    "peer0" \
    "peer0.org1.example.com" "localhost"

  infoln "Generating the user msp"
  set -x
  fabric-ca-client enroll -u https://user1:user1pw@localhost:7054 --caname ca-org1 -M "${PWD}/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp" --csr.keyrequest.algo fndsa512 --tls.certfiles "${PWD}/organizations/fabric-ca/org1/tls-cert.pem"
  { set +x; } 2>/dev/null

  cp "${PWD}/organizations/peerOrganizations/org1.example.com/msp/config.yaml" "${PWD}/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/config.yaml"
  cp "${PWD}/organizations/fabric-ca/org1/caliper-ca-cert.pem" "${PWD}/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/cacerts/caliper-ca-org1.pem"

  infoln "Generating the org admin msp"
  set -x
  fabric-ca-client enroll -u https://org1admin:org1adminpw@localhost:7054 --caname ca-org1 -M "${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp" --csr.keyrequest.algo fndsa512 --tls.certfiles "${PWD}/organizations/fabric-ca/org1/tls-cert.pem"
  { set +x; } 2>/dev/null

  cp "${PWD}/organizations/peerOrganizations/org1.example.com/msp/config.yaml" "${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/config.yaml"
  cp "${PWD}/organizations/fabric-ca/org1/caliper-ca-cert.pem" "${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/cacerts/caliper-ca-org1.pem"

  infoln "Generating ECDSA Caliper client identity for org1 (Node.js-compatible)"
  generateCaliperCert \
    "${PWD}/organizations/fabric-ca/org1" \
    "${PWD}/organizations/peerOrganizations/org1.example.com/users/caliper@org1.example.com" \
    "caliper@org1.example.com"
}

function createOrg2() {
  infoln "Enrolling the CA admin"
  mkdir -p organizations/peerOrganizations/org2.example.com/

  export FABRIC_CA_CLIENT_HOME=${PWD}/organizations/peerOrganizations/org2.example.com/

  set -x
  fabric-ca-client enroll -u https://admin:adminpw@localhost:8054 --caname ca-org2 --csr.keyrequest.algo fndsa512 --tls.certfiles "${PWD}/organizations/fabric-ca/org2/tls-cert.pem"
  { set +x; } 2>/dev/null

  # Generate ECDSA Caliper CA for org2 and add to MSP cacerts
  createCaliperCA "${PWD}/organizations/fabric-ca/org2" "org2.example.com"
  cp "${PWD}/organizations/fabric-ca/org2/caliper-ca-cert.pem" \
     "${PWD}/organizations/peerOrganizations/org2.example.com/msp/cacerts/caliper-ca-org2.pem"

  echo 'NodeOUs:
  Enable: true
  ClientOUIdentifier:
    Certificate: cacerts/caliper-ca-org2.pem
    OrganizationalUnitIdentifier: client
  PeerOUIdentifier:
    Certificate: cacerts/localhost-8054-ca-org2.pem
    OrganizationalUnitIdentifier: peer
  AdminOUIdentifier:
    Certificate: cacerts/localhost-8054-ca-org2.pem
    OrganizationalUnitIdentifier: admin
  OrdererOUIdentifier:
    Certificate: cacerts/localhost-8054-ca-org2.pem
    OrganizationalUnitIdentifier: orderer' > "${PWD}/organizations/peerOrganizations/org2.example.com/msp/config.yaml"

  # Generate ECDSA TLS CA for org2
  createTLSCA "${PWD}/organizations/fabric-ca/org2" "org2.example.com"

  # Copy TLS CA cert to org-level tlscacerts directory (for channel MSP definition)
  mkdir -p "${PWD}/organizations/peerOrganizations/org2.example.com/msp/tlscacerts"
  cp "${PWD}/organizations/fabric-ca/org2/tls-ca-cert.pem" "${PWD}/organizations/peerOrganizations/org2.example.com/msp/tlscacerts/ca.crt"

  # Copy TLS CA cert to org-level /tlsca directory (for use by clients)
  mkdir -p "${PWD}/organizations/peerOrganizations/org2.example.com/tlsca"
  cp "${PWD}/organizations/fabric-ca/org2/tls-ca-cert.pem" "${PWD}/organizations/peerOrganizations/org2.example.com/tlsca/tlsca.org2.example.com-cert.pem"

  # Copy org2's PQC CA cert to org2's /ca directory (for use by clients)
  mkdir -p "${PWD}/organizations/peerOrganizations/org2.example.com/ca"
  cp "${PWD}/organizations/fabric-ca/org2/ca-cert.pem" "${PWD}/organizations/peerOrganizations/org2.example.com/ca/ca.org2.example.com-cert.pem"

  infoln "Registering peer0"
  set -x
  fabric-ca-client register --caname ca-org2 --id.name peer0 --id.secret peer0pw --id.type peer --tls.certfiles "${PWD}/organizations/fabric-ca/org2/tls-cert.pem"
  { set +x; } 2>/dev/null

  infoln "Registering user"
  set -x
  fabric-ca-client register --caname ca-org2 --id.name user1 --id.secret user1pw --id.type client --tls.certfiles "${PWD}/organizations/fabric-ca/org2/tls-cert.pem"
  { set +x; } 2>/dev/null

  infoln "Registering the org admin"
  set -x
  fabric-ca-client register --caname ca-org2 --id.name org2admin --id.secret org2adminpw --id.type admin --tls.certfiles "${PWD}/organizations/fabric-ca/org2/tls-cert.pem"
  { set +x; } 2>/dev/null

  infoln "Generating the peer0 msp"
  set -x
  fabric-ca-client enroll -u https://peer0:peer0pw@localhost:8054 --caname ca-org2 -M "${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/msp" --csr.keyrequest.algo fndsa512 --tls.certfiles "${PWD}/organizations/fabric-ca/org2/tls-cert.pem"
  { set +x; } 2>/dev/null

  cp "${PWD}/organizations/peerOrganizations/org2.example.com/msp/config.yaml" "${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/msp/config.yaml"
  cp "${PWD}/organizations/fabric-ca/org2/caliper-ca-cert.pem" "${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/msp/cacerts/caliper-ca-org2.pem"

  infoln "Generating the peer0-tls certificates (ECDSA, signed by TLS CA)"
  generateTLSCert \
    "${PWD}/organizations/fabric-ca/org2" \
    "${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls" \
    "peer0" \
    "peer0.org2.example.com" "localhost"

  infoln "Generating the user msp"
  set -x
  fabric-ca-client enroll -u https://user1:user1pw@localhost:8054 --caname ca-org2 -M "${PWD}/organizations/peerOrganizations/org2.example.com/users/User1@org2.example.com/msp" --csr.keyrequest.algo fndsa512 --tls.certfiles "${PWD}/organizations/fabric-ca/org2/tls-cert.pem"
  { set +x; } 2>/dev/null

  cp "${PWD}/organizations/peerOrganizations/org2.example.com/msp/config.yaml" "${PWD}/organizations/peerOrganizations/org2.example.com/users/User1@org2.example.com/msp/config.yaml"
  cp "${PWD}/organizations/fabric-ca/org2/caliper-ca-cert.pem" "${PWD}/organizations/peerOrganizations/org2.example.com/users/User1@org2.example.com/msp/cacerts/caliper-ca-org2.pem"

  infoln "Generating the org admin msp"
  set -x
  fabric-ca-client enroll -u https://org2admin:org2adminpw@localhost:8054 --caname ca-org2 -M "${PWD}/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp" --csr.keyrequest.algo fndsa512 --tls.certfiles "${PWD}/organizations/fabric-ca/org2/tls-cert.pem"
  { set +x; } 2>/dev/null

  cp "${PWD}/organizations/peerOrganizations/org2.example.com/msp/config.yaml" "${PWD}/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp/config.yaml"
  cp "${PWD}/organizations/fabric-ca/org2/caliper-ca-cert.pem" "${PWD}/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp/cacerts/caliper-ca-org2.pem"

  infoln "Generating ECDSA Caliper client identity for org2 (Node.js-compatible)"
  generateCaliperCert \
    "${PWD}/organizations/fabric-ca/org2" \
    "${PWD}/organizations/peerOrganizations/org2.example.com/users/caliper@org2.example.com" \
    "caliper@org2.example.com"
}

function createOrderer() {
  infoln "Enrolling the CA admin"
  mkdir -p organizations/ordererOrganizations/example.com

  export FABRIC_CA_CLIENT_HOME=${PWD}/organizations/ordererOrganizations/example.com

  set -x
  fabric-ca-client enroll -u https://admin:adminpw@localhost:9054 --caname ca-orderer --csr.keyrequest.algo fndsa512 --tls.certfiles "${PWD}/organizations/fabric-ca/ordererOrg/tls-cert.pem"
  { set +x; } 2>/dev/null

  echo 'NodeOUs:
  Enable: true
  ClientOUIdentifier:
    Certificate: cacerts/localhost-9054-ca-orderer.pem
    OrganizationalUnitIdentifier: client
  PeerOUIdentifier:
    Certificate: cacerts/localhost-9054-ca-orderer.pem
    OrganizationalUnitIdentifier: peer
  AdminOUIdentifier:
    Certificate: cacerts/localhost-9054-ca-orderer.pem
    OrganizationalUnitIdentifier: admin
  OrdererOUIdentifier:
    Certificate: cacerts/localhost-9054-ca-orderer.pem
    OrganizationalUnitIdentifier: orderer' > "${PWD}/organizations/ordererOrganizations/example.com/msp/config.yaml"

  # Generate ECDSA TLS CA for orderer org
  createTLSCA "${PWD}/organizations/fabric-ca/ordererOrg" "example.com"

  # Copy TLS CA cert to orderer org's /msp/tlscacerts directory (for channel MSP definition)
  mkdir -p "${PWD}/organizations/ordererOrganizations/example.com/msp/tlscacerts"
  cp "${PWD}/organizations/fabric-ca/ordererOrg/tls-ca-cert.pem" "${PWD}/organizations/ordererOrganizations/example.com/msp/tlscacerts/tlsca.example.com-cert.pem"

  # Copy TLS CA cert to orderer org's /tlsca directory (for use by clients)
  mkdir -p "${PWD}/organizations/ordererOrganizations/example.com/tlsca"
  cp "${PWD}/organizations/fabric-ca/ordererOrg/tls-ca-cert.pem" "${PWD}/organizations/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem"

# Loop through each orderer (orderer, orderer2, orderer3, orderer4) to register and generate artifacts
  for ORDERER in orderer orderer2 orderer3 orderer4; do
    infoln "Registering ${ORDERER}"
    set -x
    fabric-ca-client register --caname ca-orderer --id.name ${ORDERER} --id.secret ${ORDERER}pw --id.type orderer --tls.certfiles "${PWD}/organizations/fabric-ca/ordererOrg/tls-cert.pem"
    { set +x; } 2>/dev/null

    infoln "Generating the ${ORDERER} MSP"
    set -x
    fabric-ca-client enroll -u https://${ORDERER}:${ORDERER}pw@localhost:9054 --caname ca-orderer -M "${PWD}/organizations/ordererOrganizations/example.com/orderers/${ORDERER}.example.com/msp" --csr.keyrequest.algo fndsa512 --tls.certfiles "${PWD}/organizations/fabric-ca/ordererOrg/tls-cert.pem"
    { set +x; } 2>/dev/null

    cp "${PWD}/organizations/ordererOrganizations/example.com/msp/config.yaml" "${PWD}/organizations/ordererOrganizations/example.com/orderers/${ORDERER}.example.com/msp/config.yaml"

    # Workaround: Rename the signcert file to ensure consistency with Cryptogen generated artifacts
    mv "${PWD}/organizations/ordererOrganizations/example.com/orderers/${ORDERER}.example.com/msp/signcerts/cert.pem" "${PWD}/organizations/ordererOrganizations/example.com/orderers/${ORDERER}.example.com/msp/signcerts/${ORDERER}.example.com-cert.pem"

    infoln "Generating the ${ORDERER} TLS certificates (ECDSA, signed by TLS CA)"
    generateTLSCert \
      "${PWD}/organizations/fabric-ca/ordererOrg" \
      "${PWD}/organizations/ordererOrganizations/example.com/orderers/${ORDERER}.example.com/tls" \
      "${ORDERER}" \
      "${ORDERER}.example.com" "localhost"

    # Copy TLS CA cert to orderer's /msp/tlscacerts directory (for orderer MSP definition)
    mkdir -p "${PWD}/organizations/ordererOrganizations/example.com/orderers/${ORDERER}.example.com/msp/tlscacerts"
    cp "${PWD}/organizations/fabric-ca/ordererOrg/tls-ca-cert.pem" "${PWD}/organizations/ordererOrganizations/example.com/orderers/${ORDERER}.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"
  done

  # Register and generate artifacts for the orderer admin
  infoln "Registering the orderer admin"
  set -x
  fabric-ca-client register --caname ca-orderer --id.name ordererAdmin --id.secret ordererAdminpw --id.type admin --tls.certfiles "${PWD}/organizations/fabric-ca/ordererOrg/tls-cert.pem"
  { set +x; } 2>/dev/null

  infoln "Generating the admin msp"
  set -x
  fabric-ca-client enroll -u https://ordererAdmin:ordererAdminpw@localhost:9054 --caname ca-orderer -M "${PWD}/organizations/ordererOrganizations/example.com/users/Admin@example.com/msp" --csr.keyrequest.algo fndsa512 --tls.certfiles "${PWD}/organizations/fabric-ca/ordererOrg/tls-cert.pem"
  { set +x; } 2>/dev/null

  cp "${PWD}/organizations/ordererOrganizations/example.com/msp/config.yaml" "${PWD}/organizations/ordererOrganizations/example.com/users/Admin@example.com/msp/config.yaml"
}
