import type { Finding, ImageFormat, MetadataInspectionResult } from "./types.js";

interface PayloadRange { readonly start: number; readonly end: number }

function ascii(data: Uint8Array, offset: number, value: string): boolean {
  if (offset < 0 || offset + value.length > data.length) return false;
  for (let index = 0; index < value.length; index++) if (data[offset + index] !== value.charCodeAt(index)) return false;
  return true;
}

function u16be(data: Uint8Array, offset: number): number {
  return data[offset]! * 256 + data[offset + 1]!;
}

function u32be(data: Uint8Array, offset: number): number {
  return data[offset]! * 0x1000000 + data[offset + 1]! * 0x10000 + data[offset + 2]! * 0x100 + data[offset + 3]!;
}

function u32le(data: Uint8Array, offset: number): number {
  return data[offset]! + data[offset + 1]! * 0x100 + data[offset + 2]! * 0x10000 + data[offset + 3]! * 0x1000000;
}

function exifRanges(data: Uint8Array, format: ImageFormat): PayloadRange[] {
  const ranges: PayloadRange[] = [];
  if (format === "jpeg") {
    let cursor = 2;
    while (cursor + 4 <= data.length && data[cursor] === 0xff) {
      while (cursor < data.length && data[cursor] === 0xff) cursor++;
      if (cursor >= data.length) break;
      const marker = data[cursor++]!;
      if (marker === 0xd9 || marker === 0xda) break;
      if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
      if (cursor + 2 > data.length) break;
      const length = u16be(data, cursor);
      if (length < 2 || length > data.length - cursor) break;
      const payloadStart = cursor + 2;
      const payloadEnd = cursor + length;
      if (marker === 0xe1 && ascii(data, payloadStart, "Exif\0\0")) ranges.push({ start: payloadStart + 6, end: payloadEnd });
      cursor = payloadEnd;
    }
  } else if (format === "png" && data.length >= 8) {
    let cursor = 8;
    while (cursor + 12 <= data.length) {
      const length = u32be(data, cursor);
      if (length > data.length - cursor - 12) break;
      const kind = String.fromCharCode(...data.subarray(cursor + 4, cursor + 8));
      const start = cursor + 8;
      if (kind === "eXIf") ranges.push({ start, end: start + length });
      cursor += 12 + length;
      if (kind === "IEND") break;
    }
  } else if (format === "webp" && data.length >= 12 && ascii(data, 0, "RIFF") && ascii(data, 8, "WEBP")) {
    const containerEnd = Math.min(data.length, u32le(data, 4) + 8);
    let cursor = 12;
    while (cursor + 8 <= containerEnd) {
      const kind = String.fromCharCode(...data.subarray(cursor, cursor + 4));
      const length = u32le(data, cursor + 4);
      const start = cursor + 8;
      const end = start + length;
      if (end > containerEnd) break;
      if (kind === "EXIF") ranges.push({ start: ascii(data, start, "Exif\0\0") ? start + 6 : start, end });
      cursor = end + (length & 1);
    }
  }
  return ranges;
}

interface TiffResult {
  readonly entries: number;
  readonly malformed: boolean;
  readonly sensitive: readonly { readonly id: number; readonly offset: number }[];
}

function inspectTiff(data: Uint8Array, start: number, end: number): TiffResult {
  if (end - start < 8) return { entries: 0, malformed: true, sensitive: [] };
  const little = data[start] === 0x49 && data[start + 1] === 0x49;
  if (!little && !(data[start] === 0x4d && data[start + 1] === 0x4d)) return { entries: 0, malformed: true, sensitive: [] };
  const read16 = (offset: number): number => little ? data[offset]! + data[offset + 1]! * 256 : u16be(data, offset);
  const read32 = (offset: number): number => little
    ? data[offset]! + data[offset + 1]! * 0x100 + data[offset + 2]! * 0x10000 + data[offset + 3]! * 0x1000000
    : u32be(data, offset);
  if (read16(start + 2) !== 42) return { entries: 0, malformed: true, sensitive: [] };
  const queue = [read32(start + 4)];
  const visited = new Set<number>();
  const sensitive: Array<{ id: number; offset: number }> = [];
  let entries = 0;
  while (queue.length > 0 && visited.size < 8 && entries < 1024) {
    const relative = queue.shift()!;
    if (visited.has(relative)) continue;
    visited.add(relative);
    const ifd = start + relative;
    if (relative < 8 || ifd + 2 > end) return { entries, malformed: true, sensitive };
    const count = read16(ifd);
    if (count > 1024 || ifd + 2 + count * 12 + 4 > end) return { entries, malformed: true, sensitive };
    for (let index = 0; index < count; index++) {
      const entry = ifd + 2 + index * 12;
      const tag = read16(entry);
      const type = read16(entry + 2);
      const valueCount = read32(entry + 4);
      entries++;
      if ([0x8825, 0xa430, 0xa431, 0xa435].includes(tag)) sensitive.push({ id: tag, offset: entry });
      if ((tag === 0x8769 || tag === 0x8825 || tag === 0xa005) && type === 4 && valueCount === 1) {
        const pointer = read32(entry + 8);
        if (pointer !== 0) queue.push(pointer);
      }
    }
    const nextIfd = read32(ifd + 2 + count * 12);
    if (nextIfd !== 0) queue.push(nextIfd);
  }
  if (queue.length > 0) {
    return { entries, malformed: true, sensitive };
  }
  return { entries, malformed: false, sensitive };
}

function makeFinding(id: string, severity: Finding["severity"], title: string, description: string, offset?: number, length?: number): Finding {
  return {
    id, severity, stage: "metadata", title, description,
    status: id === "META-001" ? "confirmed" : "suspected", controlStatus: id === "META-001" ? "failed" : "passed",
    evidence: [{ kind: offset === undefined ? "policy" : length === undefined ? "offset" : "range", summary: description, ...(offset === undefined ? {} : { offset }), ...(length === undefined ? {} : { length }) }]
  };
}

export function inspectMetadata(data: Uint8Array, format: ImageFormat, maxMetadataBytes: number): MetadataInspectionResult {
  if (!["jpeg", "png", "gif", "webp"].includes(format)) {
    return { status: "unsupported", metadataBytes: 0, entriesInspected: 0, findings: [] };
  }
  const findings: Finding[] = [];
  let metadataBytes = 0;
  let entriesInspected = 0;
  for (const range of exifRanges(data, format)) {
    const permittedEnd = Math.min(range.end, range.start + Math.max(0, maxMetadataBytes - metadataBytes));
    metadataBytes += permittedEnd - range.start;
    const result = inspectTiff(data, range.start, permittedEnd);
    entriesInspected += result.entries;
    if (result.malformed && permittedEnd === range.end) {
      findings.push(makeFinding("META-001", "high", "Malformed EXIF TIFF structure", "An EXIF TIFF header or IFD table is invalid or out of bounds.", range.start, range.end - range.start));
    }
    for (const tag of result.sensitive) {
      const names: Record<number, string> = { 0x8825: "GPSInfoIFDPointer", 0xa430: "OwnerName", 0xa431: "BodySerialNumber", 0xa435: "LensSerialNumber" };
      findings.push(makeFinding("META-007", "medium", "Potentially sensitive EXIF tag", `EXIF contains the ${names[tag.id]} tag; its value was not extracted.`, tag.offset, 12));
    }
    if (metadataBytes >= maxMetadataBytes) break;
  }
  return { status: "partial", metadataBytes, entriesInspected, findings };
}
