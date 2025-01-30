// ignore_for_file: non_constant_identifier_names, constant_identifier_names
import "dart:typed_data";

import "package:ffi/ffi.dart";
import "package:spake2plus/spake2plus.dart";
import "package:test/test.dart";

import "helper.dart";

void main() {
  group("spake2plus", () {
    test("randome String", () async {
      final spake2plus =
          Spake2plus(await getLibraryPath(), Uint8List(0), Uint8List(0));
      final randomString = spake2plus.randomString(16);
      expect(randomString.length, 16);
    });

    test("randome valid scalar", () async {
      final spake2plus =
          Spake2plus(await getLibraryPath(), Uint8List(0), Uint8List(0));
      final p = spake2plus.randomValidScalar();
      expect(p.length, 32);
      expect(p, isNot(Uint8List(32)));
    });

    test("ec point uncompression", () async {
      final spake2plus =
          Spake2plus(await getLibraryPath(), Uint8List(0), Uint8List(0));

      final ret = spake2plus.convertToUncompressedECPoint(
        hex2bytes(
          "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f",
        ),
      );
      expect(
        ret.toHexString(),
        "04886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20",
      );

      final ret1 = spake2plus.convertToUncompressedECPoint(
        hex2bytes(
          "04886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20",
        ),
      );
      expect(
        ret1.toHexString(),
        "04886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20",
      );
    });

    test("witness computation", () async {
      final spake2plus =
          Spake2plus(await getLibraryPath(), Uint8List(0), Uint8List(0));

      final testVectors = await loadTestVectors("spake2plus", "witness");
      final scryptParams = ScryptParameters(
          "pleaseletmein", "yellowsubmarines", 32768, 8, 1, 80);

      final (w0, w1) = spake2plus.computeWitnesses(scryptParams);

      expect(w0.toBlockedHexString(16), testVectors["w0"]);
      expect(w1.toBlockedHexString(16), testVectors["w1"]);
    });

    test("prover sample", () async {
      final testVectors = await loadTestVectors("spake2plus", "prover");
      final spake2plus = Spake2plus(
        await getLibraryPath(),
        hex2bytes(testVectors["M"]),
        hex2bytes(testVectors["N"]),
      );

      final w0 = hex2bytes(testVectors["w0"]);
      final w1 = hex2bytes(testVectors["w1"]);

      final x = hex2bytes(testVectors["x"]);
      final X = spake2plus.computeShareP(w0, x);
      expect(X.sublist(1).toBlockedHexString(16), testVectors["X"]);

      final y = hex2bytes(testVectors["y"]);
      final Y = spake2plus.computeShareV(w0, y);
      expect(Y.sublist(1).toBlockedHexString(16), testVectors["Y"]);

      final (Z, V) = spake2plus.proverFinish(w0, w1, x, Y)!;

      expect(Z.sublist(1).toBlockedHexString(16), testVectors["Z"]);
      expect(V.sublist(1).toBlockedHexString(16), testVectors["V"]);
    });

    test("verifier sample", () async {
      final testVectors = await loadTestVectors("spake2plus", "verifier");
      final spake2plus = Spake2plus(
        await getLibraryPath(),
        hex2bytes(testVectors["M"]),
        hex2bytes(testVectors["N"]),
      );

      final w0 = hex2bytes(testVectors["w0"]);
      final w1 = hex2bytes(testVectors["w1"]);

      final x = hex2bytes(testVectors["x"]);
      final X = spake2plus.computeShareP(w0, x);
      expect(X.sublist(1).toBlockedHexString(16), testVectors["X"]);

      final y = hex2bytes(testVectors["y"]);
      final Y = spake2plus.computeShareV(w0, y);
      expect(Y.sublist(1).toBlockedHexString(16), testVectors["Y"]);

      final bytesL = spake2plus.computeRecordL(w1);
      final L = Uint8List.fromList(bytesL);
      expect(L.sublist(1).toBlockedHexString(16), testVectors["L"]);

      final (Z, V) = spake2plus.verifierFinish(w0, L, X, y)!;

      expect(Z.sublist(1).toBlockedHexString(16), testVectors["Z"]);
      expect(V.sublist(1).toBlockedHexString(16), testVectors["V"]);

      expect(littleEndianBytes(X.length), [0x41, 0, 0, 0, 0, 0, 0, 0]);

      final K = spake2plus.deriveK(X, Y, Z, V, w0);
      expect(K.toBlockedHexString(16), testVectors["K"]);

      final ck = K.sublist(0, 16);
      final sk = K.sublist(16, 32);
      final infoStr = "ConfirmationKeys";
      final info = [
        ...infoStr.codeUnits,
        0x5B, 0x02, 0x01, 0x01, // TLV 5B
        0x5C, 0x04, 0x01, 0x01, 0x01, 0x0, // TLV 5C
      ];
      final (K1, K2) =
          spake2plus.deriveEvidenceKeys(ck, Uint8List.fromList(info));
      expect(K1.toBlockedHexString(16), testVectors["K1"]);
      expect(K2.toBlockedHexString(16), testVectors["K2"]);

      final M1 = spake2plus.cmacAes128(K1, X);
      final M2 = spake2plus.cmacAes128(K2, Y);
      expect(M1.toBlockedHexString(16), testVectors["M1"]);
      expect(M2.toBlockedHexString(16), testVectors["M2"]);

      final (Kenc, Kmac, Krmac, LONG_TERM_SHARED_SECRET) =
          spake2plus.derivedSystemKeys(sk);
      expect(Kenc.toBlockedHexString(16), testVectors["Kenc"]);
      expect(Kmac.toBlockedHexString(16), testVectors["Kmac"]);
      expect(Krmac.toBlockedHexString(16), testVectors["Krmac"]);
      expect(LONG_TERM_SHARED_SECRET.toBlockedHexString(16),
          testVectors["LONG_TERM_SHARED_SECRET"]);
    });
  });
}

extension Test on Spake2plus {
  Uint8List deriveK(
      Uint8List X, Uint8List Y, Uint8List Z, Uint8List V, Uint8List w0) {
    final kinput = [
      ...littleEndianBytes(X.length),
      ...X,
      ...littleEndianBytes(Y.length),
      ...Y,
      ...littleEndianBytes(Z.length),
      ...Z,
      ...littleEndianBytes(V.length),
      ...V,
      ...littleEndianBytes(w0.length),
      ...w0,
    ];
    return digestSha256(Uint8List.fromList(kinput));
  }

  (Uint8List, Uint8List) deriveEvidenceKeys(Uint8List key, Uint8List info) {
    final hash =
        deriveHkdfSha256(32, Uint8List(0), key, Uint8List.fromList(info));
    return (hash.sublist(0, 16), hash.sublist(16, 32));
  }

  (Uint8List, Uint8List, Uint8List, Uint8List) derivedSystemKeys(
      Uint8List key) {
    return using((arena) {
      final keyLen = 16;
      final str = "SystemKeys";
      final info = str.codeUnits;
      final okm =
          deriveHkdfSha256(64, Uint8List(0), key, Uint8List.fromList(info));
      final encK = okm.sublist(0, keyLen);
      final macK = okm.sublist(keyLen, keyLen * 2);
      final rmacK = okm.sublist(keyLen * 2, keyLen * 3);
      final sharedSecret = okm.sublist(keyLen * 3, keyLen * 4);
      return (encK, macK, rmacK, sharedSecret);
    });
  }
}
