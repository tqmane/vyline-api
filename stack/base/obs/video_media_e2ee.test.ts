import crypto from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { E2EE } from "../e2ee/mod.ts";
import { LineObs } from "./mod.ts";

// LINE 26.13.0: jy0/n.java selects chunk hashes for VIDEO originals;
// cq3/c.java hashes 128 KiB ciphertext blocks; cq3/g.java MACs their concatenation.
// Build the wire fixture independently of Vyline's media authentication helpers.
async function fixture(size: number, chunked = true) {
  const e2ee = new E2EE({} as never);
  const key = Buffer.alloc(32, 0x48);
  const keys = await e2ee.deriveKeyMaterial(key);
  const plain = Buffer.from(Uint8Array.from({ length: size }, (_, i) => (i * 13) & 255));
  const cipher = crypto.createCipheriv("aes-256-ctr", keys.encKey, keys.nonce);
  const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
  const hashes: Buffer[] = [];
  for (let offset = 0; offset < ciphertext.length; offset += 131072) {
    hashes.push(crypto.createHash("sha256").update(ciphertext.subarray(offset, offset + 131072)).digest());
  }
  const tag = crypto.createHmac("sha256", keys.macKey)
    .update(chunked ? Buffer.concat(hashes) : ciphertext).digest();
  const wire = Buffer.concat([ciphertext, tag]);
  const obs = new LineObs({ e2ee } as never);
  obs.downloadObjectResponseForService = async () => {
    let offset = 0;
    let fragment = 0;
    const sizes = [1, 15, 31, 32771, 200003];
    return new Response(new ReadableStream<Uint8Array>({
      pull(controller) {
        if (offset === wire.length) { controller.close(); return; }
        const end = Math.min(wire.length, offset + sizes[fragment++ % sizes.length]!);
        controller.enqueue(wire.subarray(offset, end));
        offset = end;
      },
    }), { headers: { "content-length": String(wire.length) } });
  };
  obs.downloadObjectForService = async () => new File([wire], "video.mp4");
  const message = {
    id: "video-message", to: "u-video-peer", contentType: 2,
    contentMetadata: { SID: "emv", OID: "video-object", keyMaterial: key.toString("base64") },
  };
  return { obs, message, wire, plain };
}

for (const size of [37, 131072, 262181]) {
  test(`native encrypted video authenticates across network fragments (${size} bytes)`, async () => {
    const f = await fixture(size);
    const root = await mkdtemp(join(tmpdir(), "vyline-video-auth-"));
    try {
      const target = join(root, "video.mp4");
      expect(await f.obs.downloadMediaByE2EEToFile(f.message as never, target)).toMatchObject({ size });
      expect(await readFile(target)).toEqual(f.plain);
      const buffered = await f.obs.downloadMediaByE2EE(f.message as never);
      expect(Buffer.from(await buffered!.arrayBuffer())).toEqual(f.plain);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}

test("previously sent direct-HMAC videos remain readable", async () => {
  const f = await fixture(131109, false);
  const root = await mkdtemp(join(tmpdir(), "vyline-video-legacy-"));
  try {
    const target = join(root, "video.mp4");
    await f.obs.downloadMediaByE2EEToFile(f.message as never, target);
    expect(await readFile(target)).toEqual(f.plain);
    const buffered = await f.obs.downloadMediaByE2EE(f.message as never);
    expect(Buffer.from(await buffered!.arrayBuffer())).toEqual(f.plain);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("corrupted video ciphertext and tags are rejected without publishing a file", async () => {
  const root = await mkdtemp(join(tmpdir(), "vyline-video-tamper-"));
  try {
    for (const where of [0, 131072, 131108, 131109]) {
      const f = await fixture(131109);
      f.wire[where] = f.wire[where]! ^ 1;
      const target = join(root, `bad-${where}.mp4`);
      await expect(f.obs.downloadMediaByE2EEToFile(f.message as never, target)).rejects.toThrow("authentication failed");
      expect(existsSync(target)).toBe(false);
      await expect(f.obs.downloadMediaByE2EE(f.message as never)).rejects.toThrow("authentication failed");
    }
    const image = await fixture(37);
    image.message.contentMetadata.SID = "emi";
    await expect(image.obs.downloadMediaByE2EEToFile(image.message as never, join(root, "image"))).rejects.toThrow("authentication failed");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
