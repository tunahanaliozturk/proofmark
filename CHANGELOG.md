# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/).

A change to what a probe expects is listed under its own heading, **Expectation changes**, with the citation that justifies it. Reports carry the expectations version, so results from before and after the change can be told apart.

## Unreleased

### Added

- The wire and signing layer (M1): an HTTP/1.1 client with TLS, a SigV4 signer for headers, presigned URLs and signed chunks, the `aws-chunked` encoder and decoder, CRC32, CRC32C, CRC64NVME, MD5 and SHA-256, and the fake S3 server's skeleton. No commands use them yet.
- Repository scaffold, design document, roadmap and decision records.
