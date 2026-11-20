/**
 * Small inspectors: image dimensions and RTF embedded objects.
 *
 * Images are reported by type and dimensions only. Reading what an image
 * shows (a QR code, a screenshot of a sign-in page) needs vision; see
 * "Attachments and model vision" in docs/ARCHITECTURE.md.
 */

import { InspectionContext } from './limits';
import { InspectorOutput, addFinding } from './output';
import { RealType } from './types';

/** Width and height from the image header, when the format records them simply */
export function imageDimensions(
  bytes: Buffer,
  type: RealType,
  ctx: InspectionContext
): { width: number; height: number } | undefined {
  try {
    switch (type) {
      case 'png':
        return bytes.length >= 24
          ? { width: bytes.readUInt32BE(16), height: bytes.readUInt32BE(20) }
          : undefined;
      case 'gif':
        return bytes.length >= 10
          ? { width: bytes.readUInt16LE(6), height: bytes.readUInt16LE(8) }
          : undefined;
      case 'bmp':
        return bytes.length >= 26
          ? { width: Math.abs(bytes.readInt32LE(18)), height: Math.abs(bytes.readInt32LE(22)) }
          : undefined;
      case 'jpeg': {
        // Walk marker segments to the first start-of-frame
        let p = 2;
        let segments = 0;
        while (p + 9 < bytes.length && segments++ < 1000) {
          ctx.tick();
          if (bytes[p] !== 0xff) return undefined;
          const marker = bytes[p + 1];
          if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
            p += 2;
            continue;
          }
          const length = bytes.readUInt16BE(p + 2);
          if (
            marker >= 0xc0 &&
            marker <= 0xcf &&
            marker !== 0xc4 &&
            marker !== 0xc8 &&
            marker !== 0xcc
          ) {
            return { height: bytes.readUInt16BE(p + 5), width: bytes.readUInt16BE(p + 7) };
          }
          if (length < 2) return undefined;
          p += 2 + length;
        }
        return undefined;
      }
      default:
        return undefined;
    }
  } catch {
    return undefined;
  }
}

/** RTF: embedded OLE objects (the Equation Editor exploit family lives here) */
export function inspectRtf(bytes: Buffer, ctx: InspectionContext, out: InspectorOutput): void {
  const text = bytes.toString('latin1', 0, Math.min(bytes.length, 32 * 1024 * 1024));
  ctx.checkDeadline();
  const objects = (text.match(/\\object(?![a-z])/g) ?? []).length;
  const objdata = (text.match(/\\objdata(?![a-z])/g) ?? []).length;
  addFinding(out, 'rtf_embedded_objects', Math.max(objects, objdata));
  addFinding(out, 'rtf_equation_editor', /equation\.3/i.test(text) ? 1 : 0);
  // Hyperlink fields: {\field{\*\fldinst HYPERLINK "https://..."}}
  const links = text.match(/HYPERLINK\s+"([^"]{1,2048})"/g) ?? [];
  for (const link of links.slice(0, 200)) {
    const url = /"([^"]+)"/.exec(link)?.[1];
    if (url) out.links.add(url);
  }
}
