# cmd/proteus

```sh
go install github.com/altessa-s/go-proteus/cmd/proteus@latest
```

`proteus` is the command-line tool for generating signing keys, signing plugin shared objects into detached DSSE `.so.sig` envelopes, verifying `.so` + `.so.sig` pairs, and inspecting envelopes or binaries.

## Usage

```sh
proteus keygen --alg ed25519 --private-out signing.key --public-out signing.pub
proteus sign --key signing.key --name greeter --version 1.2.0 ./greeter.so
proteus verify --key signing.pub ./greeter.so
proteus inspect ./greeter.so.sig
```
