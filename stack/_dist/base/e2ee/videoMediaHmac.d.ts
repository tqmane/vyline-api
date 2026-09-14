/** LINE Android 26.13.0 cq3/{c,g,f}.java: HMAC of SHA-256 hashes of
 * 128 KiB ciphertext blocks, including the final partial block. Network chunks
 * need not align with these blocks. No video body or hash list is retained. */
export declare function createVideoMediaHmac(macKey: Uint8Array): {
    update(bytes: Uint8Array): void;
    digest(): Buffer;
};
