#!/usr/bin/env bash
# gen_test_certs.sh — (re)generate the TLS test credentials in tests/tls/.
#
# TEST ONLY: these private keys are published in the repository.  They exist
# so unit tests, demos and blackbox tests have a fixed CA, an ECDSA P-256
# server certificate for pyro-dead01.local, and an RSA certificate.
#
#   tests/tls/gen_test_certs.sh      (needs OpenSSL 3)

set -euo pipefail
cd "$(dirname "$0")"
DAYS=7300

openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days "$DAYS" \
  -subj "/CN=smallest_tcp test CA" -out ca.pem \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -key server.key -subj "/CN=pyro-dead01.local" -out server.csr
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days "$DAYS" -sha256 -out server.pem -extfile <(printf '%s\n' \
  "subjectAltName=DNS:pyro-dead01.local,DNS:localhost,IP:10.0.0.2" \
  "basicConstraints=CA:FALSE" "keyUsage=digitalSignature" \
  "extendedKeyUsage=serverAuth")

openssl genrsa -out rsa.key 2048
openssl req -new -key rsa.key -subj "/CN=rsa.example" -out rsa.csr
openssl x509 -req -in rsa.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days "$DAYS" -sha256 -out rsa.pem -extfile <(printf '%s\n' \
  "subjectAltName=DNS:rsa.example" "keyUsage=digitalSignature")

rm -f server.csr rsa.csr ca.srl
# PKCS#8 keys (what mbedtls_pk_parse_key and OpenSSL both read)
for k in ca server rsa; do
  openssl pkcs8 -topk8 -nocrypt -in "$k.key" -out "$k.key.tmp" && mv "$k.key.tmp" "$k.key"
done
echo "regenerated: ca.pem ca.key server.pem server.key rsa.pem rsa.key"
