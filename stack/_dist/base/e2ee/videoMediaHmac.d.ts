/** LINE Android 26.13.0 cq3/{c,g,f}.java: HMAC of SHA-256 hashes of
 * 128 KiB ciphertext blocks, including the final partial block. Network chunks
 * need not align with these blocks. Senders may collect the emitted hashes;
 * receivers retain neither the video body nor a hash list. */
export declare function createVideoMediaHmac(macKey: Uint8Array, onBlockHash?: (hash: Buffer) => void): {
    update(bytes: Uint8Array): void;
    digest(): Buffer;
};
