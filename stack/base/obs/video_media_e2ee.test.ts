import crypto from "node:crypto";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { E2EE } from "../e2ee/mod.ts";
import { encryptE2eeMediaFile, LineObs } from "./mod.ts";

function nativeHashes(ciphertext: Buffer): Buffer {
  const hashes: Buffer[] = [];
  for (let offset = 0; offset < ciphertext.length; offset += 131072)
    hashes.push(crypto.createHash("sha256").update(ciphertext.subarray(offset, offset + 131072)).digest());
  return Buffer.concat(hashes);
}

function nativeTag(ciphertext: Buffer, macKey: Uint8Array, video = true): Buffer {
  return crypto.createHmac("sha256", macKey).update(video ? nativeHashes(ciphertext) : ciphertext).digest();
}

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
  const tag = nativeTag(ciphertext, keys.macKey, chunked);
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
  return { obs, message, wire, plain, e2ee, key, keys };
}

for (const size of [1, 131071, 131072, 131073, 262181]) {
  test(`outgoing encrypted video matches the strict native wire format (${size} bytes)`, async () => {
    const f = await fixture(size);
    const root = await mkdtemp(join(tmpdir(), "vyline-video-outgoing-"));
    try {
      const source = join(root, "source.mp4");
      const target = join(root, "encrypted");
      await writeFile(source, f.plain);
      const streamed = await encryptE2eeMediaFile(source, target, f.keys, size, undefined, true);
      expect(await readFile(target)).toEqual(f.wire);
      expect(streamed.videoHashes).toEqual(nativeHashes(f.wire.subarray(0, -32)));
      const buffered = await f.e2ee.encryptByKeyMaterial(f.plain, f.key, true);
      expect(buffered.encryptedData).toEqual(f.wire);
      expect(buffered.videoHashes).toEqual(streamed.videoHashes);
    } finally { await rm(root, { recursive: true, force: true }); }
  });
}

for (const staged of [false, true]) {
  for (const withPreview of [false, true]) test(`${staged ? "file" : "Blob"} video upload sends native hashes with preview=${withPreview}`, async () => {
    const f = await fixture(131077);
    const preview = Buffer.from("synthetic image preview");
    const uploads: Array<{ bytes: Buffer; path: string; filename?: string }> = [];
    let metadata: Record<string, string> = {};
    const obs = new LineObs({ e2ee: {
      deriveKeyMaterial: f.e2ee.deriveKeyMaterial.bind(f.e2ee),
      encryptByKeyMaterial: f.e2ee.encryptByKeyMaterial.bind(f.e2ee),
      encryptE2EEMessage: async () => [Buffer.from("synthetic envelope")],
    }, talk: { sendMessage: async (message: { contentMetadata: Record<string, string> }) => {
      metadata = message.contentMetadata;
      return { ...message, id: "synthetic-video" };
    } } } as never);
    obs.uploadObjectForService = (async (upload: { data: Blob; obsPath: string; filename?: string }) => {
      uploads.push({ bytes: Buffer.from(await upload.data.arrayBuffer()), path: upload.obsPath, filename: upload.filename });
      return { objId: "synthetic-object", headers: new Headers() };
    }) as never;
    const root = await mkdtemp(join(tmpdir(), "vyline-video-upload-"));
    try {
      if (staged) {
        const source = join(root, "source.mp4");
        const poster = join(root, "preview.jpg");
        await writeFile(source, f.plain); await writeFile(poster, preview);
        await obs.uploadMediaByE2EEFromFile({ dataPath: source, size: f.plain.length,
          mimeType: "video/mp4", oType: "video", to: "u-synthetic", filename: "source.mp4",
          ...(withPreview ? { previewPath: poster, previewSize: preview.length } : {}) });
      } else {
        await obs.uploadMediaByE2EE({ data: new Blob([f.plain], { type: "video/mp4" }),
          oType: "video", to: "u-synthetic", filename: "source.mp4", ...(withPreview ? { preview: new Blob([preview]) } : {}) });
      }
      expect(uploads).toHaveLength(withPreview ? 3 : 2);
      expect(metadata.SID).toBe("emv");
      expect(metadata.FILE_SIZE).toBe(String(f.plain.length));
      expect(JSON.parse(metadata.MEDIA_CONTENT_INFO!).fileSize).toBe(f.plain.length);
      const keys = await f.e2ee.deriveKeyMaterial(Buffer.from(metadata.keyMaterial!, "base64"));
      for (let index = 0; index < (withPreview ? 2 : 1); index++) {
        const wire = uploads[index]!.bytes;
        const ciphertext = wire.subarray(0, -32);
        expect(wire.subarray(-32)).toEqual(nativeTag(ciphertext, keys.macKey, index === 0));
        const decipher = crypto.createDecipheriv("aes-256-ctr", keys.encKey, keys.nonce);
        expect(Buffer.concat([decipher.update(ciphertext), decipher.final()])).toEqual(index === 0 ? f.plain : preview);
      }
      const hash = uploads.at(-1)!;
      expect(hash.path).toBe("talk/emv/synthetic-object__ud-hash");
      expect(hash.filename).toBe("hash");
      expect(hash.bytes).toEqual(nativeHashes(uploads[0]!.bytes.subarray(0, -32)));
      expect(uploads.some(upload => upload.path.endsWith("__ud-preview"))).toBe(withPreview);
    } finally { await rm(root, { recursive: true, force: true }); }
  });
}

test("a failed video hash upload never sends a message and removes temporary ciphertext", async () => {
  const f = await fixture(131077);
  let sent = 0;
  const failure = new Error("synthetic hash upload rejected");
  const obs = new LineObs({ e2ee: {
    deriveKeyMaterial: f.e2ee.deriveKeyMaterial.bind(f.e2ee),
    encryptE2EEMessage: async () => [Buffer.from("synthetic envelope")],
  }, talk: { sendMessage: async () => { sent++; return { id: "must-not-send" }; } } } as never);
  obs.uploadObjectForService = (async (upload: { data: Blob; obsPath: string }) => {
    await upload.data.arrayBuffer();
    if (upload.obsPath.endsWith("__ud-hash")) throw failure;
    return { objId: "synthetic-object", headers: new Headers() };
  }) as never;
  const root = await mkdtemp(join(tmpdir(), "vyline-video-upload-fail-"));
  try {
    const source = join(root, "source.mp4");
    await writeFile(source, f.plain);
    await expect(obs.uploadMediaByE2EEFromFile({ dataPath: source, size: f.plain.length,
      mimeType: "video/mp4", oType: "video", to: "u-synthetic", filename: "source.mp4" })).rejects.toBe(failure);
    expect(sent).toBe(0);
    expect(await readdir(root)).toEqual(["source.mp4"]);
  } finally { await rm(root, { recursive: true, force: true }); }
});

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
