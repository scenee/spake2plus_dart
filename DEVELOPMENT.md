# Developer Guide

## Pre-requisites

### macOS

1. Install [Dart](https://dart.dev/get-dart)/[Flutter](https://docs.flutter.dev/get-started/install) sdk
2. Install `openssl` via Homebrew or MacPorts

  ```sh
  sudo brew install openssl@3 # Homebrew
  sudo port install openssl3  # MacPorts
  ```

## Getting Started

1. Generate openssl.dart

```sh
dart run ffigen --config ffigen.yaml
```

