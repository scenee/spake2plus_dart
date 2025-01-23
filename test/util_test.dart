import "package:spake2plus/src/util.dart";
import "package:test/test.dart";

void main() {
  group("utils", () {
    test("littleEndianBytes", () {
      final ret = littleEndianBytes(0x12345678, len: 4);
      expect(ret, [0x78, 0x56, 0x34, 0x12]);

      final ret2 = littleEndianBytes(0x12345678);
      expect(ret2, [
        0x78,
        0x56,
        0x34,
        0x12,
        0x00,
        0x00,
        0x00,
        0x00,
      ]);

      final ret3 = littleEndianBytes(1, len: 4);
      expect(ret3, [0x01, 0x00, 0x00, 0x00]);

      final ret4 = littleEndianBytes(8, len: 4);
      expect(ret4, [0x08, 0x00, 0x00, 0x00]);
    });

    test("bigEndianBytes", () {
      final ret = bigEndianBytes(0x12345678, len: 4);
      expect(ret, [0x12, 0x34, 0x56, 0x78]);

      final ret2 = bigEndianBytes(0x12345678);
      expect(ret2, [0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78]);

      final ret3 = bigEndianBytes(1, len: 2);
      expect(ret3, [0x00, 0x01]);

      final ret4 = bigEndianBytes(8, len: 2);
      expect(ret4, [0x00, 0x08]);
    });
  });
}
