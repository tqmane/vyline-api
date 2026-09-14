import { createHash, createHmac } from "node:crypto";

/** LINE Android 26.13.0 cq3/{c,g,f}.java: HMAC of SHA-256 hashes of
 * 128 KiB ciphertext blocks, including the final partial block. Network chunks
 * need not align with these blocks. No video body or hash list is retained. */
export function createVideoMediaHmac(macKey: Uint8Array) {
  const hmac = createHmac("sha256", macKey);
  let block = createHash("sha256");
  let blockBytes = 0;
  return {
    update(bytes: Uint8Array): void {
      let offset = 0;
      while (offset < bytes.byteLength) {
        const end = Math.min(bytes.byteLength, offset + 131072 - blockBytes);
        block.update(bytes.subarray(offset, end));
        blockBytes += end - offset;
        offset = end;
        if (blockBytes === 131072) {
          hmac.update(block.digest());
          block = createHash("sha256");
          blockBytes = 0;
        }
      }
    },
    digest(): Buffer {
      if (blockBytes > 0) hmac.update(block.digest());
      return hmac.digest();
    },
  };
}
