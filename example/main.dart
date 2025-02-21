// ignore_for_file: non_constant_identifier_names

import "dart:io";
import "dart:typed_data";

import "package:spake2plus/spake2plus.dart";
import "package:spake2plus/src/util.dart";

void main() async {
  // Offline registration phase
  // M and N are from Table 1 (Section 4)
  final bytesM = hex2bytes(
      "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f");
  final bytesN = hex2bytes(
      "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49");
  final spake2plus = Spake2plus(await getLibraryPath(), bytesM, bytesN);
  final scryptParams =
      ScryptParameters("pleaseletmein", "yellowsubmarines", 32768, 8, 1, 80);
  final (w0, w1) = spake2plus.computeWitnesses(scryptParams);
  final recordL = spake2plus.computeRecordL(w1);

  final prover = Prover(spake2plus, scryptParams);
  final verifier = Verifier(spake2plus, w0, recordL);

  // Online authentication phase
  final shareP = prover.init();
  final ret = verifier.finish(shareP);
  if (ret == null) {
    stderr.write("Failed to finish\n");
    return;
  }
  final (shareV, confirmV) = ret;

  prover.finish(shareV);

  //  Key Schedule and Key Confirmation phase
  final confirmP = prover.confirm(confirmV);
  if (confirmP == null) {
    stderr.write("Failed to confirm\n");
    return;
  }
  assert(verifier.confirm(confirmP));

  final (sharedKeyP, sharedKeyV) = (prover.sharedKey, verifier.sharedKey);
  if (sharedKeyP == null || sharedKeyV == null) {
    stderr.write("Failed to compute shared key\n");
    return;
  }
  assert(listEquals(sharedKeyP, sharedKeyV));

  stdout.write("ok\n");
}

class Prover {
  final Spake2plus spake2plus;
  final ScryptParameters scryptParams;
  late final Uint8List w0;
  late final Uint8List w1;

  Uint8List? _x;
  Uint8List? _shareP;
  Uint8List? _shareV;

  Uint8List? _mainKey;
  Uint8List? _confirmPKey;
  Uint8List? _confirmVKey;
  Uint8List? sharedKey;

  Prover(this.spake2plus, this.scryptParams) {
    final w = spake2plus.computeWitnesses(scryptParams);
    w0 = w.$1;
    w1 = w.$2;
  }

  Uint8List init() {
    final xBytes = spake2plus.randomValidScalar();
    final shrareP = spake2plus.computeShareP(w0, xBytes);
    _x = xBytes;
    _shareP = shrareP;
    return shrareP;
  }

  void finish(Uint8List shareV) {
    final (x, X, Y) = (_x, _shareP, shareV);
    if (x == null || X == null) {
      return;
    }
    final ret = spake2plus.proverFinish(w0, w1, x, Y);
    if (ret == null) {
      return;
    }
    final (Z, V) = ret;

    final TT = spake2plus.computeTranscript(
      Uint8List(0), // context
      Uint8List(0), // idProver
      Uint8List(0), // idVerifier
      X,
      Y,
      Z,
      V,
      w0,
    );

    final mainKey = spake2plus.digestSha256(TT);
    final kdf = spake2plus.deriveHkdfSha256(64, Uint8List(0), mainKey,
        Uint8List.fromList("ConfirmationKeys".codeUnits));
    final (confirmPKey, confirmVKey) = (kdf.sublist(0, 32), kdf.sublist(32));

    final sharedKey = spake2plus.deriveHkdfSha256(
        32, Uint8List(0), mainKey, Uint8List.fromList("SharedKey".codeUnits));
    _mainKey = mainKey;
    _confirmPKey = confirmPKey;
    _confirmVKey = confirmVKey;
    _shareV = Y;
    this.sharedKey = sharedKey;
  }

  Uint8List? confirm(Uint8List confirmV) {
    final (X, Y, mainKey, confirmPKey, confirmVKey) =
        (_shareP, _shareV, _mainKey, _confirmPKey, _confirmVKey);
    if (X == null ||
        Y == null ||
        mainKey == null ||
        confirmPKey == null ||
        confirmVKey == null) {
      return null;
    }
    final expectedConfirmV = spake2plus.hmacSha256(confirmVKey, X);
    if (listEquals(confirmV, expectedConfirmV) == false) {
      return null;
    }
    final confirmP = spake2plus.hmacSha256(confirmPKey, Y);
    return confirmP;
  }
}

class Verifier {
  final Spake2plus spake2plus;
  final Uint8List w0;
  final Uint8List recordL;
  Uint8List? _shareV;
  Uint8List? _mainKey;
  Uint8List? _confirmPKey;
  Uint8List? sharedKey;

  Verifier(this.spake2plus, this.w0, this.recordL);

  (Uint8List, Uint8List)? finish(Uint8List shareP) {
    final X = shareP;
    final y = spake2plus.randomValidScalar();
    final Y = spake2plus.computeShareV(w0, y);
    final ret = spake2plus.verifierFinish(w0, recordL, X, y);
    if (ret == null) {
      return null;
    }
    final (Z, V) = ret;
    final TT = spake2plus.computeTranscript(
      Uint8List(0), // context
      Uint8List(0), // idProver
      Uint8List(0), // idVerifier
      X,
      Y,
      Z,
      V,
      w0,
    );

    final mainKey = spake2plus.digestSha256(TT);
    final kdf = spake2plus.deriveHkdfSha256(64, Uint8List(0), mainKey,
        Uint8List.fromList("ConfirmationKeys".codeUnits));
    final (confirmPKey, confirmVKey) = (kdf.sublist(0, 32), kdf.sublist(32));
    final confirmV = spake2plus.hmacSha256(confirmVKey, X);

    _shareV = Y;
    _mainKey = mainKey;
    _confirmPKey = confirmPKey;

    sharedKey = spake2plus.deriveHkdfSha256(
        32, Uint8List(0), mainKey, Uint8List.fromList("SharedKey".codeUnits));

    return (Y, confirmV);
  }

  bool confirm(Uint8List confirmP) {
    final (Y, mainKey, confirmPKey) = (_shareV, _mainKey, _confirmPKey);
    if (Y == null || mainKey == null || confirmPKey == null) {
      return false;
    }
    final expectedConfirmP = spake2plus.hmacSha256(confirmPKey, Y);
    return listEquals(confirmP, expectedConfirmP);
  }
}

// Naive [List] equality implementation.
bool listEquals<E>(List<E> list1, List<E> list2) {
  if (identical(list1, list2)) {
    return true;
  }

  if (list1.length != list2.length) {
    return false;
  }

  for (var i = 0; i < list1.length; i += 1) {
    if (list1[i] != list2[i]) {
      return false;
    }
  }

  return true;
}
