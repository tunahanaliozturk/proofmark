# Test fixtures

## `aws-signing-test-suite/v4`

Copied unchanged from [awslabs/aws-c-auth](https://github.com/awslabs/aws-c-auth/tree/main/tests/aws-signing-test-suite/v4), commit `f556deacd6e6d9dbf540ff00a9bf383688076874` (2026-11-19). Licensed under the Apache License 2.0, the same text as [LICENSE-APACHE](../../LICENSE-APACHE). `tests/sigv4_vectors.rs` explains which cases apply to S3 and why.

The files are compared byte for byte and have LF line ends, as upstream, so `.gitattributes` keeps git from converting them. Copy them with `git -c core.autocrlf=false archive`; a checkout with `core.autocrlf` on gives them Windows line ends.

## `tls`

A throwaway CA and a server certificate for `localhost` and `127.0.0.1`, valid until 2126, used only by the TLS tests against the fake server. `tls/server.key` is a throwaway test key for `localhost` and `127.0.0.1` and protects nothing. The CA key was deleted after signing and was never committed. To make new ones:

```
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.pem -days 36500 \
  -subj "/CN=proofmark test CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout server.key -out server.csr -subj "/CN=localhost"
printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n" > ext.cnf
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 36500 -extfile ext.cnf
openssl pkcs8 -topk8 -nocrypt -in server.key -out server.key.pk8 && mv server.key.pk8 server.key
rm ca.key server.csr ext.cnf ca.srl
```
