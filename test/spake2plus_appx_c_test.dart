// ignore_for_file: non_constant_identifier_names, constant_identifier_names
import "dart:typed_data";

import "package:spake2plus/spake2plus.dart";
import "package:test/test.dart";

import "helper.dart";

const M = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f";
const N = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49";

void main() {
  group("rfc 9383 appendix c. 2023-12-12", () {
    test("SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256", () async {
      final testName = "SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256";
      final spake2plus =
          Spake2plus(await getLibraryPath(), hex2bytes(M), hex2bytes(N));
      final testVectors = await loadTestVectors("spake2plus", testName);
      final w0 = hex2bytes(testVectors["w0"]);
      final w1 = hex2bytes(testVectors["w1"]);

      final x = hex2bytes(testVectors["x"]);
      final X = spake2plus.computeShareP(w0, x);
      expect(X.toHexString(), testVectors["shareP"]);

      final y = hex2bytes(testVectors["y"]);
      final Y = spake2plus.computeShareV(w0, y);
      expect(Y.toHexString(), testVectors["shareV"]);

      final bytesL = spake2plus.computeRecordL(w1);
      final L = Uint8List.fromList(bytesL);
      expect(L.toHexString(), testVectors["L"]);

      final (Z, V) = spake2plus.verifierFinish(w0, L, X, y)!;

      expect(Z.toHexString(), testVectors["Z"]);
      expect(V.toHexString(), testVectors["V"]);

      final (Zp, Vp) = spake2plus.proverFinish(w0, w1, x, Y)!;
      expect(Zp.toHexString(), testVectors["Z"]);
      expect(Vp.toHexString(), testVectors["V"]);

      final TT = spake2plus.computeTranscript(
        "$testName Test Vectors".toBytes(),
        "client".toBytes(),
        "server".toBytes(),
        X,
        Y,
        Z,
        V,
        w0,
      );
      expect(
        TT.toHexString(),
        testVectors["TT"]?.replaceAll(RegExp(r"\s+"), ""),
      );
      final K_main = spake2plus.digestSha256(TT);
      expect(K_main.toHexString(), testVectors["K_main"]);

      final kdf = spake2plus.deriveHkdfSha256(
          64, Uint8List(0), K_main, "ConfirmationKeys".toBytes());
      final (K_confirmP, K_confirmV) = (kdf.sublist(0, 32), kdf.sublist(32));
      expect(K_confirmP.toHexString(), testVectors["K_confirmP"]);
      expect(K_confirmV.toHexString(), testVectors["K_confirmV"]);

      final confirmP = spake2plus.hmacSha256(K_confirmP, Y);
      expect(confirmP.toHexString(), testVectors["HMAC_K_confirmP_shareV"]);
      final confirmV = spake2plus.hmacSha256(K_confirmV, X);
      expect(confirmV.toHexString(), testVectors["HMAC_K_confirmV_shareP"]);

      final K_shared = spake2plus.deriveHkdfSha256(
          32, Uint8List(0), K_main, "SharedKey".toBytes());
      expect(K_shared.toHexString(), testVectors["K_shared"]);
    });
    test("SPAKE2+-P256-SHA512-HKDF-SHA512-HMAC-SHA512", () async {
      final testName = "SPAKE2+-P256-SHA512-HKDF-SHA512-HMAC-SHA512";
      final spake2plus =
          Spake2plus(await getLibraryPath(), hex2bytes(M), hex2bytes(N));
      final testVectors = await loadTestVectors("spake2plus", testName);
      final w0 = hex2bytes(testVectors["w0"]);
      final w1 = hex2bytes(testVectors["w1"]);

      final x = hex2bytes(testVectors["x"]);
      final X = spake2plus.computeShareP(w0, x);
      expect(X.toHexString(), testVectors["shareP"]);

      final y = hex2bytes(testVectors["y"]);
      final Y = spake2plus.computeShareV(w0, y);
      expect(Y.toHexString(), testVectors["shareV"]);

      final bytesL = spake2plus.computeRecordL(w1);
      final L = Uint8List.fromList(bytesL);
      expect(L.toHexString(), testVectors["L"]);

      final (Z, V) = spake2plus.verifierFinish(w0, L, X, y)!;

      expect(Z.toHexString(), testVectors["Z"]);
      expect(V.toHexString(), testVectors["V"]);

      final (Zp, Vp) = spake2plus.proverFinish(w0, w1, x, Y)!;
      expect(Zp.toHexString(), testVectors["Z"]);
      expect(Vp.toHexString(), testVectors["V"]);

      final TT = spake2plus.computeTranscript(
        "$testName Test Vectors".toBytes(),
        "client".toBytes(),
        "server".toBytes(),
        X,
        Y,
        Z,
        V,
        w0,
      );
      expect(
        TT.toHexString(),
        testVectors["TT"]?.replaceAll(RegExp(r"\s+"), ""),
      );
      final K_main = spake2plus.digestSha512(TT);
      expect(K_main.toHexString(), testVectors["K_main"]);

      final kdf = spake2plus.deriveHkdfSha512(
          128, Uint8List(0), K_main, "ConfirmationKeys".toBytes());
      final (K_confirmP, K_confirmV) = (kdf.sublist(0, 64), kdf.sublist(64));
      expect(K_confirmP.toHexString(), testVectors["K_confirmP"]);
      expect(K_confirmV.toHexString(), testVectors["K_confirmV"]);

      final confirmP = spake2plus.hmacSha512(K_confirmP, Y);
      expect(confirmP.toHexString(), testVectors["HMAC_K_confirmP_shareV"]);
      final confirmV = spake2plus.hmacSha512(K_confirmV, X);
      expect(confirmV.toHexString(), testVectors["HMAC_K_confirmV_shareP"]);

      final K_shared = spake2plus.deriveHkdfSha512(
          64, Uint8List(0), K_main, "SharedKey".toBytes());
      expect(K_shared.toHexString(), testVectors["K_shared"]);
    });
    test("SPAKE2+-P256-SHA256-HKDF-SHA256-CMAC-AES-128", () async {
      final testName = "SPAKE2+-P256-SHA256-HKDF-SHA256-CMAC-AES-128";
      final spake2plus =
          Spake2plus(await getLibraryPath(), hex2bytes(M), hex2bytes(N));
      final testVectors = await loadTestVectors("spake2plus", testName);
      final w0 = hex2bytes(testVectors["w0"]);
      final w1 = hex2bytes(testVectors["w1"]);

      final x = hex2bytes(testVectors["x"]);
      final X = spake2plus.computeShareP(w0, x);
      expect(X.toHexString(), testVectors["shareP"]);

      final y = hex2bytes(testVectors["y"]);
      final Y = spake2plus.computeShareV(w0, y);
      expect(Y.toHexString(), testVectors["shareV"]);

      final bytesL = spake2plus.computeRecordL(w1);
      final L = Uint8List.fromList(bytesL);
      expect(L.toHexString(), testVectors["L"]);

      final (Z, V) = spake2plus.verifierFinish(w0, L, X, y)!;

      expect(Z.toHexString(), testVectors["Z"]);
      expect(V.toHexString(), testVectors["V"]);

      final (Zp, Vp) = spake2plus.proverFinish(w0, w1, x, Y)!;
      expect(Zp.toHexString(), testVectors["Z"]);
      expect(Vp.toHexString(), testVectors["V"]);

      final TT = spake2plus.computeTranscript(
        "$testName Test Vectors".toBytes(),
        "client".toBytes(),
        "server".toBytes(),
        X,
        Y,
        Z,
        V,
        w0,
      );
      expect(
        TT.toHexString(),
        testVectors["TT"]?.replaceAll(RegExp(r"\s+"), ""),
      );
      final K_main = spake2plus.digestSha256(TT);
      expect(K_main.toHexString(), testVectors["K_main"]);

      final kdf = spake2plus.deriveHkdfSha256(
          32, Uint8List(0), K_main, "ConfirmationKeys".toBytes());
      final (K_confirmP, K_confirmV) = (kdf.sublist(0, 16), kdf.sublist(16));
      expect(K_confirmP.toHexString(), testVectors["K_confirmP"]);
      expect(K_confirmV.toHexString(), testVectors["K_confirmV"]);

      final confirmP = spake2plus.cmacAes128(K_confirmP, Y);
      expect(confirmP.toHexString(), testVectors["CMAC_K_confirmP_shareV"]);
      final confirmV = spake2plus.cmacAes128(K_confirmV, X);
      expect(confirmV.toHexString(), testVectors["CMAC_K_confirmV_shareP"]);

      final K_shared = spake2plus.deriveHkdfSha256(
          32, Uint8List(0), K_main, "SharedKey".toBytes());
      expect(K_shared.toHexString(), testVectors["K_shared"]);
    });
    test("SPAKE2+-P256-SHA512-HKDF-SHA512-CMAC-AES-128", () async {
      final testName = "SPAKE2+-P256-SHA512-HKDF-SHA512-CMAC-AES-128";
      final spake2plus =
          Spake2plus(await getLibraryPath(), hex2bytes(M), hex2bytes(N));
      final testVectors = await loadTestVectors("spake2plus", testName);
      final w0 = hex2bytes(testVectors["w0"]);
      final w1 = hex2bytes(testVectors["w1"]);

      final x = hex2bytes(testVectors["x"]);
      final X = spake2plus.computeShareP(w0, x);
      expect(X.toHexString(), testVectors["shareP"]);

      final y = hex2bytes(testVectors["y"]);
      final Y = spake2plus.computeShareV(w0, y);
      expect(Y.toHexString(), testVectors["shareV"]);

      final bytesL = spake2plus.computeRecordL(w1);
      final L = Uint8List.fromList(bytesL);
      expect(L.toHexString(), testVectors["L"]);

      final (Z, V) = spake2plus.verifierFinish(w0, L, X, y)!;

      expect(Z.toHexString(), testVectors["Z"]);
      expect(V.toHexString(), testVectors["V"]);

      final (Zp, Vp) = spake2plus.proverFinish(w0, w1, x, Y)!;
      expect(Zp.toHexString(), testVectors["Z"]);
      expect(Vp.toHexString(), testVectors["V"]);

      final TT = spake2plus.computeTranscript(
        "$testName Test Vectors".toBytes(),
        "client".toBytes(),
        "server".toBytes(),
        X,
        Y,
        Z,
        V,
        w0,
      );
      expect(
        TT.toHexString(),
        testVectors["TT"]?.replaceAll(RegExp(r"\s+"), ""),
      );
      final K_main = spake2plus.digestSha512(TT);
      expect(K_main.toHexString(), testVectors["K_main"]);

      final kdf = spake2plus.deriveHkdfSha512(
          32, Uint8List(0), K_main, "ConfirmationKeys".toBytes());
      final (K_confirmP, K_confirmV) = (kdf.sublist(0, 16), kdf.sublist(16));
      expect(K_confirmP.toHexString(), testVectors["K_confirmP"]);
      expect(K_confirmV.toHexString(), testVectors["K_confirmV"]);

      final confirmP = spake2plus.cmacAes128(K_confirmP, Y);
      expect(confirmP.toHexString(), testVectors["CMAC_K_confirmP_shareV"]);
      final confirmV = spake2plus.cmacAes128(K_confirmV, X);
      expect(confirmV.toHexString(), testVectors["CMAC_K_confirmV_shareP"]);

      final K_shared = spake2plus.deriveHkdfSha512(
          64, Uint8List(0), K_main, "SharedKey".toBytes());
      expect(K_shared.toHexString(), testVectors["K_shared"]);
    });
  });
}
