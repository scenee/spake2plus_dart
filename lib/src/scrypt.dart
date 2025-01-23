import "dart:convert";
import "dart:ffi" as ffi;
import "package:ffi/ffi.dart";
import "openssl.dart";

class ScryptParameters {
  final String pwd; // an octet string
  final String salt; // an octet string
  final int cost; // Ncscypt
  final int blockSize; // r
  final int parallelization; // p
  final int dkLen;

  ScryptParameters(this.pwd, this.salt, this.cost, this.blockSize,
      this.parallelization, this.dkLen);
}

extension Scrypt on OpenSSL {
  ffi.Pointer<ffi.UnsignedChar> deriveScryptKey(
      String pwd, String salt, int cost, int blockSize, int parallel, int dkLen,
      [int scryptMaxLen = 128 * 1024 * 1024]) {
    final dk = calloc<ffi.UnsignedChar>(dkLen);

    final pwdBytes = pwd.toNativeUtf8();
    final pwdlen = utf8.encode(pwd).length;

    final saltBytes = salt.toNativeUtf8();
    final saltlen = utf8.encode(salt).length;

    EVP_PBE_scrypt(
      pwdBytes.cast(),
      pwdlen,
      saltBytes.cast(),
      saltlen,
      cost,
      blockSize,
      parallel,
      scryptMaxLen,
      dk,
      dkLen,
    );

    calloc.free(saltBytes);
    calloc.free(pwdBytes);

    return dk;
  }
}
