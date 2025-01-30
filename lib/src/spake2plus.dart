import "dart:ffi" as ffi;
import "dart:math";
import "dart:typed_data";
import "package:ffi/ffi.dart";
import "package:spake2plus/src/scrypt.dart";
import "util.dart";
import "openssl_ext.dart";
import "openssl.dart";

// Spake2+ protocol implementation
// https://datatracker.ietf.org/doc/rfc9383/
// For now, this implementation is limited to the following options:
//  * Elliptic curve: P256
//  * PBKDF: scrypt
class Spake2plus {
  final OpenSSL _openssl;
  final Uint8List _curvePointM; // a big-endian bytes of M point
  final Uint8List _curvePointN; // a big-endian bytes of N point

  Spake2plus(String libraryPath, List<int> curvePointM, List<int> curvePointN)
      : _openssl = OpenSSL(ffi.DynamicLibrary.open(libraryPath)),
        _curvePointM = Uint8List.fromList(curvePointM),
        _curvePointN = Uint8List.fromList(curvePointN);

  T _context<T>(
      T Function(
        ffi.Pointer<EC_GROUP>,
        ffi.Pointer<BN_CTX>,
        ffi.Pointer<BIGNUM>,
      ) fn) {
    final group = _openssl.EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    final ctx = _openssl.BN_CTX_new();
    final order = _openssl.BN_new();
    final res = _openssl.EC_GROUP_get_order(group, order, ctx);
    if (res != 1) {
      throw Exception("Failed to get order of the curve");
    }
    try {
      return fn(group, ctx, order);
    } finally {
      _openssl.BN_CTX_free(ctx);
      _openssl.EC_GROUP_free(group);
      _openssl.BN_free(order);
    }
  }

  (Uint8List, Uint8List) computeWitnesses(ScryptParameters scryptParams) {
    return _context((group, ctx, order) {
      return _computeWitnesses(scryptParams, group, ctx, order);
    });
  }

  (Uint8List, Uint8List) _computeWitnesses(
    ScryptParameters scryptParams,
    ffi.Pointer<EC_GROUP> group,
    ffi.Pointer<BN_CTX> ctx,
    ffi.Pointer<BIGNUM> order,
  ) {
    final w0 = _openssl.BN_new();
    final w1 = _openssl.BN_new();
    final dk = _openssl.deriveScryptKey(
      scryptParams.pwd,
      scryptParams.salt,
      scryptParams.cost,
      scryptParams.blockSize,
      scryptParams.parallelization,
      scryptParams.dkLen,
    );
    final mid = scryptParams.dkLen ~/ 2;
    final z0 = _openssl.BN_bin2bn(dk, mid, ffi.nullptr);
    final z1 = _openssl.BN_bin2bn(dk + mid, mid, ffi.nullptr);

    _openssl.calculateW(w0, z0, order, ctx);
    _openssl.calculateW(w1, z1, order, ctx);

    assert(_openssl.BN_cmp(w0, w1) == 1);

    final w0Bytes = _openssl.bn2bytes(group, w0, 32, ctx);
    final w1Bytes = _openssl.bn2bytes(group, w1, 32, ctx);

    _openssl.BN_free(z1);
    _openssl.BN_free(z0);
    _openssl.BN_free(w0);
    _openssl.BN_free(w1);

    calloc.free(dk);

    return (w0Bytes, w1Bytes);
  }

  String randomString(int length) {
    final rand = Random.secure();
    final codeUnits = List.generate(length, (index) {
      return rand.nextInt(26) + 97;
    });
    return String.fromCharCodes(codeUnits);
  }

  Uint8List randomValidScalar() {
    return _context((group, ctx, order) {
      final p = _openssl.BN_new();
      _openssl.BN_rand_range(p, order);
      final ret = _openssl.bn2bytes(group, p, 32, ctx);
      _openssl.BN_free(p);
      return ret;
    });
  }

  // shareP = X
  Uint8List computeShareP(Uint8List w0bytes, Uint8List xBytes) {
    return _context((group, ctx, order) {
      final w0 = _openssl.BN_new();
      _openssl.bytes2bn(w0, w0bytes);

      final M = _openssl.EC_POINT_new(group);
      _openssl.bytes2point(group, M, _curvePointM, ctx);

      final x = _openssl.BN_new();
      _openssl.bytes2bn(x, xBytes);

      final X = _openssl.calculatePoint(group, ctx, x, M, w0);

      final bytesX = _openssl.point2bytes(group, X, ctx);

      _openssl.EC_POINT_free(X);
      _openssl.BN_free(x);
      _openssl.EC_POINT_free(M);
      _openssl.BN_free(w0);

      return bytesX;
    });
  }

  // shareV = Y
  Uint8List computeShareV(Uint8List w0Bytes, Uint8List yBytes) {
    return _context((group, ctx, _) {
      final w0 = _openssl.BN_new();
      _openssl.bytes2bn(w0, w0Bytes);

      final N = _openssl.EC_POINT_new(group);
      _openssl.bytes2point(group, N, _curvePointN, ctx);

      final y = _openssl.BN_new();
      _openssl.bytes2bn(y, yBytes);

      final Y = _openssl.calculatePoint(group, ctx, y, N, w0);

      final bytesY = _openssl.point2bytes(group, Y, ctx);

      _openssl.BN_free(y);
      _openssl.BN_free(w0);
      _openssl.EC_POINT_free(Y);
      _openssl.EC_POINT_free(N);

      return bytesY;
    });
  }

  Uint8List computeRecordL(Uint8List w1Bytes) {
    return _context((group, ctx, _) {
      final w1 = _openssl.BN_new();
      final L = _openssl.EC_POINT_new(group);

      _openssl.bytes2bn(w1, w1Bytes);
      _openssl.EC_POINT_mul(
          group, L, w1, ffi.nullptr, ffi.nullptr, ctx); // w1 * G

      final bytesL = _openssl.point2bytes(group, L, ctx);

      _openssl.BN_free(w1);
      _openssl.EC_POINT_free(L);

      return bytesL;
    });
  }

  (Uint8List Z, Uint8List V)? proverFinish(Uint8List w0Bytes, Uint8List w1Bytes,
      Uint8List xBytes, Uint8List bytesY) {
    return _context((group, ctx, _) {
      final Y = _openssl.EC_POINT_new(group);
      _openssl.bytes2point(group, Y, bytesY, ctx);
      final ok = (_openssl.EC_POINT_is_on_curve(group, Y, ctx) == 1) &&
          (_openssl.EC_POINT_is_at_infinity(group, Y) == 0);

      if (!ok) {
        _openssl.EC_POINT_free(Y);
        return null;
      }

      final N = _openssl.EC_POINT_new(group);
      _openssl.bytes2point(group, N, _curvePointN, ctx);

      final x = _openssl.BN_new();
      _openssl.bytes2bn(x, xBytes);

      final w0 = _openssl.BN_new();
      _openssl.bytes2bn(w0, w0Bytes);

      final w1 = _openssl.BN_new();
      _openssl.bytes2bn(w1, w1Bytes);

      final Z = _openssl.calculateZ(group, ctx, Y, N, w0, x);
      final V = _openssl.calculateV_prover(group, ctx, Y, N, w0, w1, x);

      final bytesZ = _openssl.point2bytes(group, Z, ctx);
      final bytesV = _openssl.point2bytes(group, V, ctx);

      _openssl.EC_POINT_free(V);
      _openssl.EC_POINT_free(Z);
      _openssl.EC_POINT_free(N);
      _openssl.EC_POINT_free(Y);
      _openssl.BN_free(w1);
      _openssl.BN_free(w0);
      _openssl.BN_free(x);

      return (bytesZ, bytesV);
    });
  }

  (Uint8List Z, Uint8List V)? verifierFinish(
    Uint8List w0Bytes,
    Uint8List bytesL,
    Uint8List bytesX,
    Uint8List yBytes,
  ) {
    return _context((group, ctx, _) {
      final X = _openssl.EC_POINT_new(group);
      _openssl.bytes2point(group, X, bytesX, ctx);
      final ok = (_openssl.EC_POINT_is_on_curve(group, X, ctx) == 1) &&
          (_openssl.EC_POINT_is_at_infinity(group, X) == 0);

      if (!ok) {
        _openssl.EC_POINT_free(X);
        return null;
      }

      final M = _openssl.EC_POINT_new(group);
      _openssl.bytes2point(group, M, _curvePointM, ctx);

      final L = _openssl.EC_POINT_new(group);
      _openssl.bytes2point(group, L, bytesL, ctx);

      final w0 = _openssl.BN_new();
      _openssl.bytes2bn(w0, w0Bytes);
      final y = _openssl.BN_new();
      _openssl.bytes2bn(y, yBytes);

      final Z = _openssl.calculateZ(group, ctx, X, M, w0, y);
      final V = _openssl.calculateV_verifier(group, ctx, L, y);

      final bytesZ = _openssl.point2bytes(group, Z, ctx);
      final bytesV = _openssl.point2bytes(group, V, ctx);

      _openssl.EC_POINT_free(V);
      _openssl.EC_POINT_free(Z);
      _openssl.EC_POINT_free(L);
      _openssl.EC_POINT_free(M);
      _openssl.EC_POINT_free(X);
      _openssl.BN_free(w0);
      _openssl.BN_free(y);

      return (bytesZ, bytesV);
    });
  }

  Uint8List computeTranscript(
    Uint8List context,
    Uint8List idProver,
    Uint8List idVerifier,
    Uint8List bytesX,
    Uint8List bytesY,
    Uint8List bytesZ,
    Uint8List bytesV,
    Uint8List w0Bytes,
  ) {
    final uncompressedM = convertToUncompressedECPoint(_curvePointM);
    final uncompressedN = convertToUncompressedECPoint(_curvePointN);
    return Uint8List.fromList([
      ...littleEndianBytes(context.length),
      ...context,
      ...littleEndianBytes(idProver.length),
      ...idProver,
      ...littleEndianBytes(idVerifier.length),
      ...idVerifier,
      ...littleEndianBytes(uncompressedM.length),
      ...uncompressedM,
      ...littleEndianBytes(uncompressedN.length),
      ...uncompressedN,
      ...littleEndianBytes(bytesX.length),
      ...bytesX,
      ...littleEndianBytes(bytesY.length),
      ...bytesY,
      ...littleEndianBytes(bytesZ.length),
      ...bytesZ,
      ...littleEndianBytes(bytesV.length),
      ...bytesV,
      ...littleEndianBytes(w0Bytes.length),
      ...w0Bytes,
    ]);
  }

  Uint8List digestSha256(Uint8List transcript) {
    return _digest(SN_sha256, transcript);
  }

  Uint8List digestSha512(Uint8List transcript) {
    return _digest(SN_sha512, transcript);
  }

  Uint8List _digest(String sn, Uint8List input) {
    final datalen = input.length;
    final data = calloc<ffi.UnsignedChar>(datalen);
    for (var i = 0; i < datalen; i++) {
      data[i] = input[i];
    }
    final ffi.Pointer<EVP_MD> type;
    final int buflen;
    if (sn == SN_sha256) {
      type = _openssl.EVP_sha256();
      buflen = 32;
    } else if (sn == SN_sha512) {
      type = _openssl.EVP_sha512();
      buflen = 64;
    } else {
      throw ArgumentError("Unsupported digest algorithm: $sn");
    }
    final hash = calloc<ffi.UnsignedChar>(buflen);
    final mdlen = calloc<ffi.UnsignedInt>(1);
    _openssl.EVP_Digest(
      data.cast(),
      datalen,
      hash,
      mdlen,
      type,
      ffi.nullptr,
    );
    final outlen = mdlen.value;

    final bytes =
        Uint8List.fromList(hash.cast<ffi.Uint8>().asTypedList(outlen));

    calloc.free(data);
    calloc.free(mdlen);
    calloc.free(hash);

    return bytes;
  }

  Uint8List deriveHkdfSha256(
    int L,
    Uint8List salt,
    Uint8List key,
    Uint8List info,
  ) {
    return _deriveHkdf(_openssl.EVP_sha256(), L, salt, key, info);
  }

  Uint8List deriveHkdfSha512(
    int L,
    Uint8List salt,
    Uint8List key,
    Uint8List info,
  ) {
    return _deriveHkdf(_openssl.EVP_sha512(), L, salt, key, info);
  }

  Uint8List _deriveHkdf(
    ffi.Pointer<EVP_MD> md,
    int L,
    Uint8List salt,
    Uint8List key,
    Uint8List info,
  ) {
    return using((Arena arena) {
      final pctx = _openssl.EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, ffi.nullptr);
      if (pctx == ffi.nullptr) return Uint8List(0);

      _openssl.EVP_PKEY_derive_init(pctx);
      _openssl.EVP_PKEY_CTX_set_hkdf_md(pctx, md);
      final s = salt.toPointer(allocator: arena);
      _openssl.EVP_PKEY_CTX_set1_hkdf_salt(pctx, s, salt.length);
      final k = key.toPointer(allocator: arena);
      _openssl.EVP_PKEY_CTX_set1_hkdf_key(pctx, k, key.length);
      final i = info.toPointer(allocator: arena);
      _openssl.EVP_PKEY_CTX_add1_hkdf_info(pctx, i, info.length);

      final keylen = arena<ffi.Size>(1);
      keylen.value = L;
      final derivedKey = calloc<ffi.UnsignedChar>(keylen.value);
      _openssl.EVP_PKEY_derive(pctx, derivedKey, keylen);
      _openssl.EVP_PKEY_CTX_free(pctx);

      return Uint8List.fromList(derivedKey.cast<ffi.Uint8>().asTypedList(L));
    });
  }

  Uint8List cmacAes128(Uint8List key, Uint8List data) {
    final cmac = _openssl.cmacAes128(key, data);
    final ret =
        Uint8List.fromList((cmac as ffi.Pointer<ffi.Uint8>).asTypedList(16));
    calloc.free(cmac);
    return ret;
  }

  Uint8List hmacSha256(Uint8List key, Uint8List data) {
    final hmac = _openssl.hmacSha256(key, data);
    final ret =
        Uint8List.fromList((hmac as ffi.Pointer<ffi.Uint8>).asTypedList(32));
    calloc.free(hmac);
    return ret;
  }

  Uint8List hmacSha512(Uint8List key, Uint8List data) {
    final hmac = _openssl.hmacSha512(key, data);
    final ret =
        Uint8List.fromList((hmac as ffi.Pointer<ffi.Uint8>).asTypedList(64));
    calloc.free(hmac);
    return ret;
  }

  Uint8List convertToUncompressedECPoint(Uint8List pointData) {
    return _context((group, ctx, _) {
      final cp = _openssl.EC_POINT_new(group);
      final buf = pointData.toPointer();
      _openssl.EC_POINT_oct2point(group, cp, buf, pointData.length, ctx);

      final len = 65;
      final ptr = calloc<ffi.UnsignedChar>(len);
      _openssl.EC_POINT_point2oct(
        group,
        cp,
        point_conversion_form_t.POINT_CONVERSION_UNCOMPRESSED,
        ptr,
        len,
        ctx,
      );
      final ret = Uint8List.fromList(ptr.cast<ffi.Uint8>().asTypedList(len));
      _openssl.EC_POINT_free(cp);
      calloc.free(buf);
      calloc.free(ptr);
      return ret;
    });
  }
}
