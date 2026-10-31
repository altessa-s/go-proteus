# signing

Package `signing` provides key generation (`GenerateKey`), private key PEM loading (`ParsePrivateKeyPEM` backed by
`go-tlsutils`), manifest construction (`BuildManifest`), DSSE envelope signing (`SignManifest`, `SignFile`), and atomic file writing
(`WriteFileAtomic`).

## Supported Algorithms

- `signature.AlgEd25519` (default)
- `signature.AlgECDSAP256`

RSA and other curves are rejected with `signature.ErrKeyPolicy`.
