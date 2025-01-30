import "dart:ffi" as ffi;
import "dart:ffi";
import "dart:io";
import "dart:typed_data";

import "package:ffi/ffi.dart";

Future<String> getLibraryPath() async {
  String path = "";
  if (Platform.isLinux) {
    for (final dir in [
      "/usr/lib/x86_64-linux-gnu",
      "/usr/lib/aarch64-linux-gnu/"
    ]) {
      final List<FileSystemEntity> entities = await Directory(dir)
          .list(recursive: true, followLinks: false)
          .where((e) => e.path.contains("libcrypto.so"))
          .toList();
      if (entities.isNotEmpty) {
        path = entities.first.path;
        break;
      }
    }
  } else if (Platform.isMacOS) {
    for (final dir in [
      "/opt/homebrew/Cellar/openssl@3", // Homebrew
      "/opt/local/libexec/openssl3", // MacPorts
    ]) {
      final directory = Directory(dir);
      if (!await directory.exists()) {
        continue;
      }
      final List<FileSystemEntity> entities = await directory
          .list(recursive: true, followLinks: false)
          .where((e) => e.path.contains("libcrypto.dylib"))
          .toList();
      if (entities.isNotEmpty) {
        path = entities.first.path;
        break;
      }
    }
  }
  if (path.isEmpty) {
    throw UnsupportedError("Unsupported platform");
  }
  return path;
}

Uint8List hex2bytes(String? hexString) {
  if (hexString == null) {
    return Uint8List(0);
  }
  hexString = hexString.replaceAll(RegExp(r"\s+"), "");
  hexString = hexString.replaceAll(RegExp(r"\n"), "");
  final len = hexString.length ~/ 2;
  final ret = Uint8List(len);
  for (var i = 0; i < len; i++) {
    ret[i] = int.parse(hexString.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return ret;
}

Uint8List littleEndianBytes(int value, {int len = 8}) {
  if (len <= 0) {
    return Uint8List(0);
  }

  final bytes = Uint8List(len);
  for (var i = 0; i < len; i++) {
    bytes[i] = (value >> (i * 8)) & 0xff;
  }
  return bytes;
}

Uint8List bigEndianBytes(int value, {int len = 8}) {
  if (len <= 0) {
    return Uint8List(0);
  }

  final bytes = Uint8List(len);
  final last = len - 1;
  for (var i = 0; i < len; i++) {
    bytes[last - i] = (value >> (i * 8)) & 0xff;
  }
  return bytes;
}

extension StringPointer on String {
  ffi.Pointer<T> toPointer<T extends ffi.NativeType>(
      {Allocator allocator = calloc}) {
    final p = allocator<ffi.UnsignedChar>(length);
    for (var i = 0; i < codeUnits.length; i++) {
      p[i] = codeUnits[i];
    }
    return p.cast<T>();
  }
}

extension Uint8ListPointer on Uint8List {
  ffi.Pointer<ffi.UnsignedChar> toPointer({Allocator allocator = calloc}) {
    final p = allocator<ffi.UnsignedChar>(length);
    for (var i = 0; i < length; i++) {
      p[i] = this[i];
    }
    return p;
  }
}
