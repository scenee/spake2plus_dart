import "dart:ffi" as ffi;
import "dart:typed_data";
import "package:ffi/ffi.dart";
import "openssl.dart";
import "util.dart";

extension OpenSSLSpake2plus on OpenSSL {
  void calculateW(
    ffi.Pointer<BIGNUM> w,
    ffi.Pointer<BIGNUM> z,
    ffi.Pointer<BIGNUM> order,
    ffi.Pointer<BN_CTX> ctx,
  ) {
    final n_1 = BN_dup(order);
    BN_sub_word(n_1, 1);
    BN_div(ffi.nullptr, w, z, n_1, ctx);
    BN_add_word(w, 1);
    BN_free(n_1);
  }

  ffi.Pointer<EC_POINT> calculatePoint(
    ffi.Pointer<EC_GROUP> group,
    ffi.Pointer<BN_CTX> ctx,
    ffi.Pointer<BIGNUM> scalar,
    ffi.Pointer<EC_POINT> point,
    ffi.Pointer<BIGNUM> w,
  ) {
    final p = EC_POINT_new(group);
    EC_POINT_mul(group, p, scalar, point, w, ctx);
    return p;
  }

  ffi.Pointer<EC_POINT> calculateZ(
    ffi.Pointer<EC_GROUP> group,
    ffi.Pointer<BN_CTX> ctx,
    ffi.Pointer<EC_POINT> point,
    ffi.Pointer<EC_POINT> base,
    ffi.Pointer<BIGNUM> w0,
    ffi.Pointer<BIGNUM> scalar,
  ) {
    final p = EC_POINT_new(group);
    final temp = EC_POINT_new(group);
    EC_POINT_mul(group, temp, ffi.nullptr, base, w0, ctx);
    EC_POINT_invert(group, temp, ctx);
    EC_POINT_add(group, temp, point, temp, ctx);
    EC_POINT_mul(group, p, ffi.nullptr, temp, scalar, ctx);
    EC_POINT_free(temp);
    return p;
  }

  // ignore: non_constant_identifier_names
  ffi.Pointer<EC_POINT> calculateV_verifier(
    ffi.Pointer<EC_GROUP> group,
    ffi.Pointer<BN_CTX> ctx,
    ffi.Pointer<EC_POINT> point,
    ffi.Pointer<BIGNUM> scalar,
  ) {
    final p = EC_POINT_new(group);
    EC_POINT_mul(group, p, ffi.nullptr, point, scalar, ctx);
    return p;
  }

  // ignore: non_constant_identifier_names
  ffi.Pointer<EC_POINT> calculateV_prover(
    ffi.Pointer<EC_GROUP> group,
    ffi.Pointer<BN_CTX> ctx,
    ffi.Pointer<EC_POINT> point,
    ffi.Pointer<EC_POINT> base,
    ffi.Pointer<BIGNUM> w0,
    ffi.Pointer<BIGNUM> w1,
    ffi.Pointer<BIGNUM> scalar,
  ) {
    final p = EC_POINT_new(group);
    final temp = EC_POINT_new(group);
    EC_POINT_mul(group, temp, ffi.nullptr, base, w0, ctx);
    EC_POINT_invert(group, temp, ctx);
    EC_POINT_add(group, temp, point, temp, ctx);
    EC_POINT_mul(group, p, ffi.nullptr, temp, w1, ctx);
    EC_POINT_free(temp);
    return p;
  }

  ffi.Pointer<ffi.UnsignedChar> cmacAes128(Uint8List key, Uint8List data) {
    return _cmac(SN_aes_128_cbc, key, data, 16);
  }

  ffi.Pointer<ffi.UnsignedChar> cmacAes256(Uint8List key, Uint8List data) {
    return _cmac(SN_aes_256_cbc, key, data, 32);
  }

  ffi.Pointer<ffi.UnsignedChar> hmacSha256(Uint8List key, Uint8List data) {
    return _hmac(SN_sha256, key, data, 32);
  }

  ffi.Pointer<ffi.UnsignedChar> hmacSha512(Uint8List key, Uint8List data) {
    return _hmac(SN_sha512, key, data, 64);
  }

  ffi.Pointer<ffi.UnsignedChar> _cmac(
    String chiper,
    Uint8List key,
    Uint8List data,
    int outlen,
  ) {
    return using((arena) {
      final keyPtr = key.toPointer(allocator: arena);
      final keylen = key.length;
      final dataPtr = data.toPointer(allocator: arena);
      final datalen = data.length;

      final cmac = calloc<ffi.UnsignedChar>(outlen); // not freed
      final cmacSize = arena<ffi.Size>(1);

      final mac = EVP_MAC_fetch(
        ffi.nullptr,
        OSSL_MAC_NAME_CMAC.toPointer(allocator: arena),
        ffi.nullptr,
      );
      final mctx = EVP_MAC_CTX_new(mac);

      final params = arena<OSSL_PARAM>(2);
      params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_MAC_PARAM_CIPHER.toPointer(allocator: arena),
        chiper.toPointer(allocator: arena),
        chiper.codeUnits.length,
      );
      params[1] = OSSL_PARAM_construct_end();

      EVP_MAC_init(mctx, keyPtr.cast(), keylen, params);
      EVP_MAC_update(mctx, dataPtr, datalen);
      EVP_MAC_final(mctx, cmac, cmacSize, outlen);

      EVP_MAC_CTX_free(mctx);

      assert(cmacSize.value == outlen);

      return cmac;
    });
  }

  ffi.Pointer<ffi.UnsignedChar> _hmac(
    String digest,
    Uint8List key,
    Uint8List data,
    int outlen,
  ) {
    return using((arena) {
      final keyPtr = key.toPointer(allocator: arena);
      final keylen = key.length;
      final dataPtr = data.toPointer(allocator: arena);
      final datalen = data.length;

      final hmac = calloc<ffi.UnsignedChar>(outlen); // not freed
      final hmacSize = arena<ffi.Size>(1);

      final mac = EVP_MAC_fetch(
        ffi.nullptr,
        OSSL_MAC_NAME_HMAC.toPointer(allocator: arena),
        ffi.nullptr,
      );
      final mctx = EVP_MAC_CTX_new(mac);

      final params = arena<OSSL_PARAM>(2);
      params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_MAC_PARAM_DIGEST.toPointer(allocator: arena),
        digest.toPointer(allocator: arena),
        digest.codeUnits.length,
      );
      params[1] = OSSL_PARAM_construct_end();

      EVP_MAC_init(mctx, keyPtr.cast(), keylen, params);
      EVP_MAC_update(mctx, dataPtr, datalen);
      EVP_MAC_final(mctx, hmac, hmacSize, outlen);

      EVP_MAC_CTX_free(mctx);

      assert(hmacSize.value == outlen);

      return hmac;
    });
  }
}

extension OpenSSLBytes on OpenSSL {
  void bytes2bn(ffi.Pointer<BIGNUM> bn, Uint8List bytes) {
    final bin = calloc<ffi.UnsignedChar>(bytes.length);
    for (var i = 0; i < bytes.length; i++) {
      bin[i] = bytes[i];
    }
    BN_bin2bn(bin, bytes.length, bn);
    calloc.free(bin);
  }

  Uint8List bn2bytes(ffi.Pointer<EC_GROUP> group, ffi.Pointer<BIGNUM> p,
      int len, ffi.Pointer<BN_CTX> ctx) {
    final bin = calloc<ffi.UnsignedChar>(len);
    BN_bn2bin(p, bin);
    final bytes = Uint8List(len);
    for (var i = 0; i < len; i++) {
      bytes[i] = bin[i];
    }
    calloc.free(bin);
    return bytes;
  }

  Uint8List convertToUncompressedEcpoint(ffi.Pointer<EC_GROUP> group,
      ffi.Pointer<BN_CTX> ctx, Uint8List pointData) {
    final p = EC_POINT_new(group);
    final oct = pointData.toPointer();
    EC_POINT_oct2point(group, p, oct, pointData.length, ctx);
    calloc.free(oct);

    final len = 65;
    final buf = calloc<ffi.UnsignedChar>(len);
    EC_POINT_point2oct(group, p,
        point_conversion_form_t.POINT_CONVERSION_UNCOMPRESSED, buf, len, ctx);

    EC_POINT_free(p);

    final bytes = Uint8List(len);
    for (var i = 0; i < len; i++) {
      bytes[i] = buf[i];
    }
    calloc.free(buf);
    return bytes;
  }

  Uint8List point2bytes(ffi.Pointer<EC_GROUP> group, ffi.Pointer<EC_POINT> p,
      ffi.Pointer<BN_CTX> ctx) {
    final len = 65;
    final buf = calloc<ffi.UnsignedChar>(len);
    EC_POINT_point2oct(group, p,
        point_conversion_form_t.POINT_CONVERSION_UNCOMPRESSED, buf, len, ctx);
    final bytes = Uint8List(len);
    for (var i = 0; i < len; i++) {
      bytes[i] = buf[i];
    }
    calloc.free(buf);
    return bytes;
  }

  void bytes2point(ffi.Pointer<EC_GROUP> group, ffi.Pointer<EC_POINT> p,
      Uint8List bytes, ffi.Pointer<BN_CTX> ctx) {
    var buf = calloc<ffi.UnsignedChar>(bytes.length);
    for (var i = 0; i < bytes.length; i++) {
      buf[i] = bytes[i];
    }
    EC_POINT_oct2point(group, p, buf.cast(), bytes.length, ctx);
    calloc.free(buf);
  }
}
