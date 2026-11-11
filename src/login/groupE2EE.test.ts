import { expect, mock, test } from "bun:test";
import { BaseClient } from "@vyline/protocol/stack/base";
import { decryptLetterSealingMessage } from "../e2ee/letterSealing.js";
import { createKeyPair } from "../e2ee/primitives.js";
import { patchGroupKeyLookup, storeGroupKey } from "./groupE2EE.js";

async function fixture() {
  const mid = `u${"1".repeat(32)}`;
  const chatMid = `c${"2".repeat(32)}`;
  const self = createKeyPair();
  const identity = {
    keyId: 11,
    privKey: self.privKey.toString("base64"),
    pubKey: self.pubKey.toString("base64"),
  };
  const oldKey = { keyId: 31, privKey: createKeyPair().privKey.toString("base64") };
  const latestKey = { keyId: 91, privKey: createKeyPair().privKey.toString("base64") };
  const data = new Map([
    [`e2eeKeys:${mid}`, JSON.stringify(identity)],
    [`e2eeGroupKeys:${chatMid}:${oldKey.keyId}`, JSON.stringify(oldKey)],
    [`e2eeGroupKeys:${chatMid}:${latestKey.keyId}`, JSON.stringify(latestKey)],
    [`e2eeGroupKeys:${chatMid}`, JSON.stringify(latestKey)],
  ]);
  const base = new BaseClient({
    device: "IOSIPAD",
    fetch: async () => {
      throw new Error("unexpected network request in group-key test");
    },
  });
  base.profile = { mid } as NonNullable<BaseClient["profile"]>;
  for (const [key, value] of data) await base.storage.set(key, value);
  const last = mock(async () => ({
    keyVersion: 2,
    groupKeyId: latestKey.keyId,
    creator: mid,
    creatorKeyId: identity.keyId,
    receiver: mid,
    receiverKeyId: identity.keyId,
    encryptedSharedKey: "",
    allowedTypes: [1, 2],
    specVersion: 2,
  }));
  base.talk.getLastE2EEGroupSharedKey = last;
  patchGroupKeyLookup(base);
  return { base, mid, chatMid, oldKey, latestKey, last, e2ee: base.e2ee };
}

for (const contentType of [1, 2] as const) {
  test(`media type ${contentType} uses the current group key after reading old history`, async () => {
    const f = await fixture();
    // History lookup overwrites the compatibility cache with an old key.
    await f.e2ee.getE2EELocalPublicKey(f.chatMid, f.oldKey.keyId);
    const payload = { keyMaterial: Buffer.alloc(32, 7).toString("base64"), fileName: "fixture" };
    const chunks = await f.e2ee.encryptE2EEMessage(f.chatMid, payload, contentType);
    expect(chunks[4]!.readUInt32BE()).toBe(f.latestKey.keyId);
    expect(f.last).toHaveBeenCalledTimes(1);
    const decrypted = await decryptLetterSealingMessage(f.base, {
      to: f.chatMid,
      from: f.mid,
      isSelf: true,
      chunks,
      contentType,
    });
    expect(decrypted.json).toEqual(payload);
  });
}

test("group sends recheck the current key after a server rotation", async () => {
  const f = await fixture();
  await f.e2ee.getE2EELocalPublicKey(f.chatMid);
  const rotatedKey = { keyId: 92, privKey: createKeyPair().privKey.toString("base64") };
  await storeGroupKey(f.base, f.chatMid, rotatedKey);
  f.latestKey.keyId = rotatedKey.keyId;
  await f.e2ee.getE2EELocalPublicKey(f.chatMid, f.oldKey.keyId);
  expect(await f.e2ee.getE2EELocalPublicKey(f.chatMid)).toEqual(rotatedKey);
  expect(f.last).toHaveBeenCalledTimes(2);
});

test("a failed current-key lookup does not send with a cached historical key", async () => {
  const f = await fixture();
  const error = new Error("group key lookup denied");
  f.last.mockRejectedValue(error);
  await expect(f.e2ee.encryptE2EEMessage(f.chatMid, { fileName: "fixture" }, 1)).rejects.toBe(
    error,
  );
});

test("history still resolves its exact group key without requesting the latest", async () => {
  const f = await fixture();
  expect(await f.e2ee.getE2EELocalPublicKey(f.chatMid, f.oldKey.keyId)).toEqual(f.oldKey);
  expect(f.last).not.toHaveBeenCalled();
});
