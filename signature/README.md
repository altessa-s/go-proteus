# signature

Package `signature` provides Dead Simple Signing Envelope (DSSE) v1 encoding, strict JSON v2 manifest serialization, public key policy
enforcement (`Key`, `KeySet`), and cryptographic verification (`Verifier`) for `go-proteus`.

## Cryptographic Policy

- **Supported algorithms**: Ed25519 (`AlgEd25519`, default) and ECDSA P-256 (`AlgECDSAP256`).
- **Rejected algorithms**: RSA and non-P-256 elliptic curves return `signature.ErrKeyPolicy`.
- **Key IDs**: 32-character lowercase hexadecimal encoding of the first 16 bytes of SHA-256 of the SPKI (PKIX) DER-encoded public key.
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

Keys copy public material on ingestion and access; callers cannot mutate verification state through `PublicKey()`, `Lookup()`, or `Keys()`.

PEM trust bundles must be consumed completely: only PUBLIC KEY blocks and ASCII space, tab, CR, and LF separators are accepted.
Malformed blocks or other text anywhere in a bundle fail with ErrKeyPolicy; neither parsing API returns a partial trust set.
