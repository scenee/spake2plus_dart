import "dart:ffi" as ffi;

import "package:ffi/ffi.dart";
import "package:spake2plus/spake2plus.dart";
import "package:spake2plus/src/openssl.dart";
import "package:test/test.dart";

import "helper.dart";

void main() {
  group("scrypt", () {
    late final OpenSSL openssl;
    setUpAll(() {});

    test("deriveKey 1", () async {
      openssl = OpenSSL(ffi.DynamicLibrary.open(getLibraryPath()));
      final testVectors = await loadTestVectors("scrypt", "dk1");
      final dk = openssl.deriveScryptKey("", "", 16, 1, 1, 64);
      final res = dk.toBlockedHexString(64, 16);
      expect(res, testVectors["dk"]);
      calloc.free(dk);
    });
    test("deriveKey 2", () async {
      final testVectors = await loadTestVectors("scrypt", "dk2");
      final dk2 = openssl.deriveScryptKey("password", "NaCl", 1024, 8, 16, 64);
      final res2 = dk2.toBlockedHexString(64, 16);
      expect(res2, testVectors["dk"]);
      calloc.free(dk2);
    });
  });
}
