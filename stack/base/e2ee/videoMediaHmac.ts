import { createHash, createHmac } from "node:crypto";

/** LINE Android 26.13.0 cq3/{c,g,f}.java: HMAC of SHA-256 hashes of
 * 128 KiB ciphertext blocks, including the final partial block. Network chunks
 * need not align with these blocks. Senders may collect the emitted hashes;
 * receivers retain neither the video body nor a hash list. */
export function createVideoMediaHmac(macKey: Uint8Array, onBlockHash?: (hash: Buffer) => void) {
  const hmac = createHmac("sha256", macKey);
  let block = createHash("sha256");
  let blockBytes = 0;
  const finishBlock = () => {
    const hash = block.digest();
    hmac.update(hash);
    onBlockHash?.(hash);
    block = createHash("sha256");
    blockBytes = 0;
  };
  return {
    update(bytes: Uint8Array): void {
      let offset = 0;
      while (offset < bytes.byteLength) {
        const end = Math.min(bytes.byteLength, offset + 131072 - blockBytes);
        block.update(bytes.subarray(offset, end));
        blockBytes += end - offset;
        offset = end;
        if (blockBytes === 131072) {
          finishBlock();
        }
      }
    },
    digest(): Buffer {
      if (blockBytes > 0) finishBlock();
      return hmac.digest();
    },
  };
}
