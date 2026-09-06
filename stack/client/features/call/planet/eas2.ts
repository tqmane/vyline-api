/**
 * PLANET normal-audio (pmap=1) is EAS2, not raw Opus.
 * LINE 26.13 ARM64: vns_audio_pyld_hdr_parse 0x7f62a4,
 * eas2_depacketizer_depack 0x805060; single-frame TX 0x805cf4..0x805fe4.
 * The outer byte is chunk-id << 4 | silence << 3. EAS2 replaces the
 * Opus frame-count bits with speech/config flags; never decode it as Opus.
 */
export function packetizeEas2(opus: Uint8Array): Uint8Array {
  if (opus.length < 1 || opus.length > 1276 || (opus[0] & 3) !== 0) {
    throw new Error("EAS2 send requires one Opus frame");
  }
  // Our 20 ms encoder has DTX disabled: one continuous speech chunk.
  const payload = new Uint8Array(opus.length + 1);
  payload[0] = 0x10;
  payload.set(opus, 1);
  payload[1] = (opus[0] & 0xfc) | 1;
  return payload;
}

export function depacketizeEas2(payload: Uint8Array): Uint8Array[] {
  let offset = 1; // Native always consumes the chunk/silence header.
  const read = () => {
    if (offset >= payload.length) throw new Error("Truncated EAS2 packet");
    return payload[offset++];
  };
  const header = read();
  const configs = [header & 0xfc];
  let count = 1;
  let vbr = false;
  if (header & 2) {
    let config = header;
    while (!(config & 1)) {
      if (configs.length >= 48) throw new Error("Too many EAS2 configs");
      config = read();
      configs.push(config & 0xfc);
    }
    const control = read();
    count = control & 0x3f;
    vbr = (control & 0x80) !== 0;
    if (control & 0x40 || count < 1 || count > 48 || configs.length > count) {
      throw new Error("Invalid EAS2 frame count/control");
    }
    while (configs.length < count) configs.push(configs[configs.length - 1]);
    // Speech flags are present for CELT frames only, MSB first. The Opus
    // decoder doesn't need these flags, but their bytes must be consumed.
    const celtFrames = configs.filter((toc) => toc >= 0x80).length;
    for (let i = 0; i < Math.ceil(celtFrames / 8); i++) read();
  }
  const lengths: number[] = [];
  if (vbr) {
    for (let i = 1; i < count; i++) {
      const first = read();
      lengths.push(first < 252 ? first : first + 4 * read());
    }
    lengths.push(payload.length - offset - lengths.reduce((sum, size) => sum + size, 0));
  } else {
    const size = (payload.length - offset) / count;
    for (let i = 0; i < count; i++) lengths.push(size);
  }
  if (lengths.some((size) => !Number.isInteger(size) || size < 0 || size > 1275)) {
    throw new Error("Invalid EAS2 frame length");
  }
  return lengths.map((size, i) => {
    const opus = new Uint8Array(size + 1);
    opus[0] = configs[i];
    opus.set(payload.subarray(offset, offset + size), 1);
    offset += size;
    return opus;
  });
}
