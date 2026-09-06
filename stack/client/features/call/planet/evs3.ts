// PLANET_RTP AVC, Windows ampkit 1.0.0.911: PD maker 0x9a86c0,
// AVC packer 0x249260 / depacker 0x242730. This is not RFC 6184 FU-A.
export const MAX_VIDEO_FRAME_BYTES = 1024 * 1024;

export interface EncodedVideoFrame {
  /** A complete AVCC access unit, including in-band SPS/PPS on key pictures. */
  data: Uint8Array;
  key: boolean;
  /** Unsigned 90 kHz RTP timestamp. */
  timestamp: number;
}

export function validateAvcc(data: Uint8Array): void {
  if (!data.length || data.length > MAX_VIDEO_FRAME_BYTES) throw new Error("Invalid AVC size");
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let offset = 0;
  while (offset < data.length) {
    if (offset + 4 > data.length) throw new Error("Truncated AVC length");
    const length = view.getUint32(offset);
    offset += 4;
    if (length < 2 || length > data.length - offset) throw new Error("Invalid AVC NAL length");
    const nal = data[offset];
    if (nal & 0x80 || (nal & 31) < 1 || (nal & 31) > 23) throw new Error("Unsupported AVC NAL");
    offset += length;
  }
}

export function packetizeEvs3(
  data: Uint8Array,
  key: boolean,
  pictureId: number,
  fragmentBytes = 1000,
): Uint8Array[] {
  validateAvcc(data);
  if (
    !Number.isInteger(fragmentBytes) ||
    fragmentBytes < 1 ||
    fragmentBytes > 1000 ||
    Math.ceil(data.length / fragmentBytes) > 2048
  )
    throw new Error("Invalid video fragment size");
  const packets: Uint8Array[] = [];
  for (let offset = 0; offset < data.length; offset += fragmentBytes) {
    const begin = offset === 0;
    const end = offset + fragmentBytes >= data.length;
    const header = begin
      ? key
        ? [0xba, pictureId >>> 8, pictureId, 0, 0x20]
        : [0xfa, pictureId >>> 8, pictureId, 0, 3, 1, 0, 0]
      : [0x80, pictureId >>> 8, pictureId];
    if (end) header[0] |= 4;
    const body = data.subarray(offset, offset + fragmentBytes);
    const packet = new Uint8Array(header.length + body.length);
    packet.set(header);
    packet.set(body, header.length);
    packets.push(packet);
  }
  return packets;
}

export function parseEvs3(payload: Uint8Array) {
  let offset = 0;
  const read = () => {
    if (offset >= payload.length) throw new Error("Truncated EVS3 descriptor");
    return payload[offset++];
  };
  const flags = read();
  if (!(flags & 0x80)) throw new Error("EVS3 picture ID missing");
  const pictureId = (read() << 8) | read();
  const begin = Boolean(flags & 8);
  const end = Boolean(flags & 4);
  if (begin && (flags & 0x2a) !== 0x2a) throw new Error("EVS3 first descriptor incomplete");
  if (flags & 0x20) {
    const layer = read();
    // ponytail: single-layer AVC only; negotiate a layered decoder before accepting SVC.
    if (layer & 0xee) throw new Error("Unsupported EVS3 layer");
    if ((flags & 0x50) === 0x50) {
      let reference = read();
      for (let count = 1; reference & 1; count++) {
        if (count >= 3) throw new Error("Too many EVS3 references");
        reference = read();
      }
    }
  }
  let key = false;
  let rotation = 0;
  if (flags & 2) {
    const props = read();
    key = Boolean(props & 0x20);
    rotation = props >>> 6;
    if (props & 1) {
      for (let count = 0; ; count++) {
        if (count >= 8) throw new Error("Too many EVS3 extensions");
        read(); // extension type; unknown types are length-delimited
        const lengthAndLast = read();
        const length = lengthAndLast & 0x7f;
        if (!length || offset + length >= payload.length) throw new Error("Invalid EVS3 extension");
        offset += length;
        if (lengthAndLast & 0x80) break;
      }
    }
  }
  if (offset >= payload.length) throw new Error("Empty EVS3 fragment");
  return { pictureId, begin, end, key, rotation, offset };
}

interface Picture {
  id: string;
  timestamp: number;
  start: number;
  end?: number;
  key: boolean;
  since: number;
  bytes: number;
  fragments: Map<number, Uint8Array>;
}

interface VideoRtpPacket {
  payload: Uint8Array;
  seq: number;
  timestamp: number;
  ssrc: number;
  marker: boolean;
}

export class Evs3Assembler {
  #picture?: Picture;
  #latest?: { timestamp: number; ssrc: number };
  #lastSequence?: number;
  #needsKey = true;
  #early?: { id: string; since: number; bytes: number; packets: Map<number, VideoRtpPacket> };

  clear(): void {
    this.#picture = undefined;
    this.#latest = undefined;
    this.#lastSequence = undefined;
    this.#needsKey = true;
    this.#early = undefined;
  }

  push(packet: VideoRtpPacket, now = Date.now()): EncodedVideoFrame | undefined {
    try {
      const pd = parseEvs3(packet.payload);
      const id = `${packet.ssrc}/${packet.timestamp}/${pd.pictureId}`;
      if (this.#early && now - this.#early.since > 1000) this.#early = undefined;
      if (!pd.begin && !this.#picture) {
        if (!this.#isNewer(packet)) return;
        if (this.#early?.id !== id) this.#early = { id, since: now, bytes: 0, packets: new Map() };
        const early = this.#early;
        const existing = early.packets.get(packet.seq);
        if (existing) {
          if (
            existing.payload.length !== packet.payload.length ||
            existing.payload.some((b, i) => b !== packet.payload[i])
          ) {
            this.#latest = { timestamp: packet.timestamp, ssrc: packet.ssrc };
            throw new Error("Conflicting early EVS3 duplicate");
          }
          return;
        }
        early.bytes += packet.payload.length;
        if (early.bytes > MAX_VIDEO_FRAME_BYTES || early.packets.size >= 2048)
          throw new Error("Early video too large");
        early.packets.set(packet.seq, { ...packet, payload: packet.payload.slice() });
        return;
      }
      const early = pd.begin ? this.#early : undefined;
      if (pd.begin) this.#early = undefined;
      let frame = this.#push(packet, now);
      if (!frame && this.#picture && early?.id === id) {
        for (const part of [...early.packets.values()].sort(
          (a, b) => ((a.seq - packet.seq) & 0xffff) - ((b.seq - packet.seq) & 0xffff),
        )) {
          frame = this.#push(part, now);
          if (frame) break;
        }
      }
      return frame;
    } catch {
      this.#early = undefined;
      this.#discard();
      return undefined;
    }
  }

  #discard(): void {
    this.#needsKey = true;
    this.#picture = undefined;
  }

  #isNewer(packet: VideoRtpPacket): boolean {
    if (!this.#latest) return true;
    const advance = (packet.timestamp - this.#latest.timestamp) >>> 0;
    return this.#latest.ssrc === packet.ssrc && advance > 0 && advance < 0x80000000;
  }

  #push(packet: VideoRtpPacket, now: number): EncodedVideoFrame | undefined {
    const pd = parseEvs3(packet.payload);
    const id = `${packet.ssrc}/${packet.timestamp}/${pd.pictureId}`;
    if (this.#picture && now - this.#picture.since > 1000) this.#discard();
    if (this.#picture?.id !== id) {
      if (!pd.begin) {
        if (this.#picture && ((packet.seq - this.#picture.start) & 0xffff) < 2048) this.#discard();
        return;
      }
      if (!this.#isNewer(packet)) return;
      this.#latest = { timestamp: packet.timestamp, ssrc: packet.ssrc };
      if (
        this.#picture ||
        (this.#lastSequence !== undefined && packet.seq !== ((this.#lastSequence + 1) & 0xffff))
      )
        this.#discard();
      if (this.#needsKey && !pd.key) return;
      this.#picture = {
        id,
        timestamp: packet.timestamp,
        start: packet.seq,
        key: pd.key,
        since: now,
        bytes: 0,
        fragments: new Map(),
      };
    }
    const picture = this.#picture;
    const index = (packet.seq - picture.start) & 0xffff;
    if (
      index >= 2048 ||
      (pd.begin && index !== 0) ||
      pd.end !== packet.marker ||
      (picture.end !== undefined && index > picture.end)
    )
      throw new Error("Invalid EVS3 sequence");
    const existing = picture.fragments.get(index);
    if (existing) {
      if (
        existing.length !== packet.payload.length ||
        existing.some((b, i) => b !== packet.payload[i])
      ) {
        throw new Error("Conflicting EVS3 duplicate");
      }
      return;
    }
    if (pd.end) {
      if (
        (picture.end !== undefined && picture.end !== index) ||
        [...picture.fragments.keys()].some((i) => i > index)
      )
        throw new Error("Contradictory EVS3 end");
      picture.end = index;
    }
    picture.bytes += packet.payload.length - pd.offset;
    if (picture.bytes > MAX_VIDEO_FRAME_BYTES) throw new Error("EVS3 picture too large");
    picture.fragments.set(index, packet.payload.slice());
    if (picture.end === undefined || picture.fragments.size !== picture.end + 1) return;
    const data = new Uint8Array(picture.bytes);
    let offset = 0;
    for (let i = 0; i <= picture.end; i++) {
      const fragment = picture.fragments.get(i)!;
      const body = fragment.subarray(parseEvs3(fragment).offset);
      data.set(body, offset);
      offset += body.length;
    }
    validateAvcc(data);
    this.#lastSequence = (picture.start + picture.end) & 0xffff;
    this.#picture = undefined;
    this.#needsKey = false;
    return { data, key: picture.key, timestamp: picture.timestamp };
  }
}
