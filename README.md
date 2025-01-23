# spake2plus

A Dart package for SPAKE2+, an Augmented Password-Authenticated Key Exchange (PAKE) protocol [[RFC9383](https://datatracker.ietf.org/doc/rfc9383/)]. Supports Raspeberry Pi OS and macOS for now.

## Depencendies

This package uses [OpenSSL v3.4](https://github.com/openssl/openssl/releases/tag/openssl-3.4.0) via [dart:ffi](https://api.dart.dev/dart-ffi/dart-ffi-library.html).

## Supported PBKDF

| PBKDF | Status |
| :--- | :---: |
| Scrypt [[RFC7914](https://datatracker.ietf.org/doc/html/rfc7914.html)] | ✅ |
| Argon2id [[RFC9106](https://datatracker.ietf.org/doc/rfc9106/)] | ❌ |

## Supporte ECC curves and Hash, KDF and Mac algorithms

| G | Hash | KDF | MAC | Status |
| :--- | :---: | :---: | :---: | :---: |
| P-256        | SHA256 | HKDF-SHA256 | HMAC-SHA256  | ✅ |
| P-256        | SHA512 | HKDF-SHA512 | HMAC-SHA512  | ✅ |
| P-384        | SHA256 | HKDF-SHA256 | HMAC-SHA256  | ❌ |
| P-384        | SHA512 | HKDF-SHA512 | HMAC-SHA512  | ❌ |
| P-521        | SHA512 | HKDF-SHA512 | HMAC-SHA512  | ❌ |
| edwards25519 | SHA256 | HKDF-SHA256 | HMAC-SHA256  | ❌ |
| edwards448   | SHA512 | HKDF-SHA512 | HMAC-SHA512  | ❌ |
| P-256        | SHA256 | HKDF-SHA256 | CMAC-AES-128 | ✅ |
| P-256        | SHA512 | HKDF-SHA512 | CMAC-AES-128 | ✅ |

* [[RFC6234](https://datatracker.ietf.org/doc/html/rfc6234)]: SHA256/512
* [[RFC5869](https://datatracker.ietf.org/doc/html/rfc5869)]: HKDF-SHA256/SHA512
* [[RFC4493](https://datatracker.ietf.org/doc/html/rfc4493)]: HMAC-SHA256/SHA512

## Getting started

### Raspberry Pi OS

1. Install [Dart](https://dart.dev/get-dart)/[Flutter](https://docs.flutter.dev/get-started/install) sdk
2. Install `libcrypto`

```sh
sudo apt-get install libssl-dev
```

3. Check the path to `libcrypto.so`
4. Pass the library path into `Spake2plus` class constructor.

### macOS

1. Install [Dart](https://dart.dev/get-dart)/[Flutter](https://docs.flutter.dev/get-started/install) sdk
2. Install `openssl` via Homebrew or MacPorts

```sh
sudo brew install openssl@3 # Homebrew
sudo port install openssl3  # MacPorts
```

3. Check the path to `libcrypto.3.dylib`
4. Pass the library path into `Spake2plus` class constructor.
