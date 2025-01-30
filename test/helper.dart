import "dart:ffi" as ffi;
import "dart:io";
import "dart:typed_data";

import "package:yaml/yaml.dart";

extension Bytes on String {
  Uint8List toBytes() {
    return Uint8List.fromList(codeUnits);
  }
}

extension Buffer on Uint8List {
  String toHexString({String separator = ""}) {
    return map((e) => e.toRadixString(16).padLeft(2, "0")).join(separator);
  }

  String toBlockedHexString(int lineByteLen, {String separator = ""}) {
    final hexBytes = map((e) => e.toRadixString(16).padLeft(2, "0"));
    var ret = "";
    for (int i = 0; i < hexBytes.length; i += 1) {
      ret += hexBytes.elementAt(i);
      if ((i + 1) % lineByteLen == 0) {
        ret += "\n";
      } else {
        ret += separator;
      }
    }
    return ret;
  }
}

extension HexString on ffi.Pointer<ffi.UnsignedChar> {
  String toBlockedHexString(int byteLen, int lineByteLen,
      {String separator = ""}) {
    return (this as ffi.Pointer<ffi.Uint8>)
        .asTypedList(byteLen)
        .toBlockedHexString(lineByteLen, separator: separator);
  }
}

Future<Map<String, String>> loadTestVectors(
  String filename,
  String test,
) async {
  final file = File("test/test_vectors/$filename.yaml");
  final yamlString = await file.readAsString();
  final yamlMap = loadYaml(yamlString);
  final vectors = yamlMap[test]["vectors"];
  var map = <String, String>{};
  vectors.forEach((k, v) {
    map[k as String] = v as String;
  });
  return map;
}
