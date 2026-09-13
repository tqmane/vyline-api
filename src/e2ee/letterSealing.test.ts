import { expect, test } from "bun:test";
import type { BaseClient } from "@vyline/protocol/stack/base";
import { createKeyPair } from "./primitives.js";
import { decryptLetterSealingMessage, encryptLetterSealingText } from "./letterSealing.js";

test("group messages from another self device resolve the sender key by ID", async () => {
  const mid = `u${"1".repeat(32)}`;
  const chatMid = `c${"2".repeat(32)}`;
  const phone = createKeyPair();
  const desktop = createKeyPair();
  const group = { keyId: 91, privKey: createKeyPair().privKey.toString("base64") };
  const keys = (keyId: number, pair: ReturnType<typeof createKeyPair>) => ({
    keyId,
    privKey: pair.privKey.toString("base64"),
    pubKey: pair.pubKey.toString("base64"),
  });
  const resolved: Array<{ mid: string; keyVersion: number; keyId: number }> = [];
  const clientWithKey = (identity: ReturnType<typeof keys>) => {
    const data = new Map([
      [`e2eeKeys:${mid}`, JSON.stringify(identity)],
      [`e2eeGroupKeys:${chatMid}:${group.keyId}`, JSON.stringify(group)],
    ]);
    return {
      profile: { mid },
      storage: {
        async get(key: string) {
          return data.get(key) ?? null;
        },
        async set(key: string, value: string) {
          data.set(key, value);
        },
      },
      talk: {
        async getLastE2EEGroupSharedKey() {
          return { groupKeyId: group.keyId };
        },
        async getE2EEPublicKey(params: { mid: string; keyVersion: number; keyId: number }) {
          resolved.push(params);
          return { keyData: phone.pubKey };
        },
      },
    } as unknown as BaseClient;
  };
  const envelope = await encryptLetterSealingText(
    clientWithKey(keys(11, phone)),
    chatMid,
    mid,
    "phone message",
  );
  const decrypted = await decryptLetterSealingMessage(clientWithKey(keys(12, desktop)), {
    to: chatMid,
    from: mid,
    isSelf: true,
    chunks: envelope.chunks,
  });
  expect(decrypted.json).toEqual({ text: "phone message" });
  expect(resolved).toEqual([{ mid, keyVersion: 1, keyId: 11 }]);

  // Imports may have only the MID cache. Keep using it when the key ID matches.
  resolved.length = 0;
  expect(
    (
      await decryptLetterSealingMessage(clientWithKey(keys(11, phone)), {
        to: chatMid,
        from: mid,
        isSelf: true,
        chunks: envelope.chunks,
      })
    ).json,
  ).toEqual({ text: "phone message" });
  expect(resolved).toEqual([]);
});
