const crcTable = new Uint32Array(256);
for (let index = 0; index < crcTable.length; index++) {
  let value = index;
  for (let bit = 0; bit < 8; bit++) value = (value & 1) ? (value >>> 1) ^ 0xedb8_8320 : value >>> 1;
  crcTable[index] = value >>> 0;
}

/** Compute PNG CRC-32 over a bounded byte range. */
export function crc32(data: Uint8Array, start = 0, end = data.length): number {
  let value = 0xffff_ffff;
  for (let offset = start; offset < end; offset++) {
    value = (value >>> 8) ^ crcTable[(value ^ data[offset]!) & 0xff]!;
  }
  return (value ^ 0xffff_ffff) >>> 0;
}
