// Windows ampkit 1.0.0.911: SVC packetizer 0x246dc0, profile 0x24d710,
// VFD 0xef140; VP8 depacketizer 0x241c90. pmap 7/4 is not normal-video pmap 2.
import { MAX_VIDEO_FRAME_BYTES, packetizeEvs3, parseEvs3 } from "./evs3.js";

/** Single spatial/temporal VP8 layer, with one VFD record per RTP packet. */
export function packetizeSvcVp8(
  data: Uint8Array,
  key: boolean,
  pictureId: number,
  sequence: number,
  resolution: 0 | 1 | 2 | 3,
  fragmentBytes = 1000,
): Array<{ payload: Uint8Array; extensionData: Uint8Array }> {
  if (
    !Number.isInteger(sequence) ||
    sequence < 0 ||
    sequence > 65535 ||
    !Number.isInteger(resolution) ||
    resolution < 0 ||
    resolution > 3
  ) {
    throw new Error("Invalid SVC descriptor");
  }
  return packetizeEvs3(data, key, pictureId, fragmentBytes).map((fragment, index, parts) => {
    let payload = fragment;
    if (index === 0) {
      const { offset } = parseEvs3(fragment);
      payload = new Uint8Array(fragment.length + 6);
      payload.set(fragment.subarray(0, offset));
      payload.set([3, key ? 16 : 0], offset); // codec VP8=3, TID=SID=0
      new DataView(payload.buffer).setUint32(offset + 2, data.length + 3);
      payload.set(fragment.subarray(offset), offset + 6);
    }
    const seq = (sequence + index) & 65535;
    return {
      payload,
      extensionData: new Uint8Array([
        2,
        3,
        0x80 | (index === parts.length - 1 ? 0x40 : 0),
        (resolution << 4) | 8 | (key ? 4 : 0) | (index === 0 ? 2 : 0),
        3,
        0,
        seq >>> 8,
        seq & 255,
      ]),
    };
  });
}

/** Validate the SVC profile, then reuse the bounded normal-video assembler. */
export function unwrapSvcVp8(payload: Uint8Array): Uint8Array {
  const pd = parseEvs3(payload);
  if (!pd.begin) return payload;
  const offset = pd.offset;
  if (offset + 9 >= payload.length) throw new Error("Truncated SVC profile");
  // ponytail: base layer only; negotiate/decode additional layers before accepting them.
  if (payload[offset] !== 3 || payload[offset + 1] !== (pd.key ? 16 : 0)) {
    throw new Error("Unsupported SVC profile");
  }
  const length = new DataView(payload.buffer, payload.byteOffset, payload.byteLength).getUint32(
    offset + 2,
  );
  const vp8Length =
    (payload[offset + 6] & 3) | (payload[offset + 7] << 2) | (payload[offset + 8] << 10);
  if (length !== vp8Length || length < 7 || length > MAX_VIDEO_FRAME_BYTES + 3) {
    throw new Error("Invalid SVC frame length");
  }
  const normalized = new Uint8Array(payload.length - 6);
  normalized.set(payload.subarray(0, offset));
  normalized.set(payload.subarray(offset + 6), offset);
  return normalized;
}

/** VFD version 1, exactly one base-layer VP8 packet descriptor. */
export function parseSvcVfd(elements: Uint8Array, payload: Uint8Array): number {
  const pd = parseEvs3(payload);
  let sequence: number | undefined;
  for (let offset = 0; offset < elements.length; ) {
    const id = elements[offset++];
    if (!id) continue;
    if (offset >= elements.length) throw new Error("Truncated SVC extension");
    const length = elements[offset++] * 2;
    const end = offset + length;
    if (end > elements.length || id === 4) throw new Error("Unsupported SVC extension");
    if (id === 2) {
      if (
        sequence !== undefined ||
        length !== 6 ||
        elements[offset] !== (pd.end ? 0xc0 : 0x80) ||
        (elements[offset + 1] & 0xc9) !== 8 ||
        Boolean(elements[offset + 1] & 2) !== pd.begin ||
        (pd.begin && Boolean(elements[offset + 1] & 4) !== pd.key) ||
        elements[offset + 2] !== 3
      ) {
        throw new Error("Unsupported SVC VFD");
      }
      sequence = (elements[offset + 4] << 8) | elements[offset + 5];
    }
    offset = end;
  }
  if (sequence === undefined) throw new Error("SVC VFD missing");
  return sequence;
}
