# signature

Package `signature` provides Dead Simple Signing Envelope (DSSE) v1 encoding, strict JSON v2 manifest serialization, public key policy
enforcement (`Key`, `KeySet`), and cryptographic verification (`Verifier`) for `go-proteus`.

## Cryptographic Policy

- **Supported algorithms**: Ed25519 (`AlgEd25519`, default) and ECDSA P-256 (`AlgECDSAP256`).
- **Rejected algorithms**: RSA and non-P-256 elliptic curves return `signature.ErrKeyPolicy`.
- **Key IDs**: 64-character lowercase hexadecimal SHA-256 digest of the PKIX DER-encoded public key.
- **DSSE v1 PAE**: Signatures are computed over `DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>` with payload type
  `application/vnd.altessa.proteus.manifest+json`.
- **Strict JSON v2**: Both DSSE envelopes and `proteus.Manifest` payloads reject unknown members and duplicate object member names.

## Usage

```go
key, err := signature.ParsePublicKeyPEM(pemBytes)
if err != nil {
	return err
}
ks, err := signature.NewKeySet(key)
if err != nil {
	return err
}
verifier, err := signature.NewVerifier(ks)
if err != nil {
	return err
}
verified, err := verifier.Verify(ctx, sigEnvelopeBytes)
```
