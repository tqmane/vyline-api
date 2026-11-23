import { createCipheriv, createHash } from "node:crypto";
import { expect, test } from "bun:test";
import { BaseClient } from "@vyline/protocol/stack/base";
import { createKeyPair, generateSharedSecret, xorHalves } from "../e2ee/primitives.js";
import { ensureValidE2EEIdentity } from "./ensureE2EE.js";

test("decodeE2EEKeyV1 stores every valid entry in encryptedKeyChain under its own keyId", async () => {
  const base = new BaseClient({
    device: "IOSIPAD",
    fetch: async () => {
      throw new Error("unexpected network call");
    },
  });
  const serverPair = createKeyPair();
  const secretPair = createKeyPair();
  const oldKey = createKeyPair();
  const latestKey = createKeyPair();

  const shared = generateSharedSecret(secretPair.privKey, serverPair.pubKey);
  const aesKey = createHash("sha256").update(Buffer.concat([shared, Buffer.from("Key")])).digest();
  const aesIv = xorHalves(
    createHash("sha256").update(Buffer.concat([shared, Buffer.from("IV")])).digest(),
  );
  const cipher = createCipheriv("aes-256-cbc", aesKey, aesIv);
  cipher.setAutoPadding(false);
  const encryptedKeyChain = Buffer.concat([cipher.update(Buffer.alloc(32, 1)), cipher.final()]);

  base.thrift.readThriftStruct = (() => ({
    1: [
      { 2: 5530444, 4: oldKey.pubKey, 5: oldKey.privKey },
      { 2: 6115157, 4: latestKey.pubKey, 5: latestKey.privKey },
    ],
  })) as never;

  const decoded = await base.e2ee.decodeE2EEKeyV1(
    {
      keyId: 6115157,
      e2eeVersion: 1,
      publicKey: serverPair.pubKey.toString("base64"),
      encryptedKeyChain: encryptedKeyChain.toString("base64"),
    },
    secretPair.privKey,
  );

  expect(decoded?.keyId).toBe(6115157);
  expect(Buffer.from(decoded!.pubKey).toString("base64")).toBe(latestKey.pubKey.toString("base64"));

  const storedOld = JSON.parse((await base.storage.get("e2eeKeys:5530444")) as string);
  const storedLatest = JSON.parse((await base.storage.get("e2eeKeys:6115157")) as string);
  expect(storedOld.pubKey).toBe(oldKey.pubKey.toString("base64"));
  expect(storedLatest.pubKey).toBe(latestKey.pubKey.toString("base64"));
});

test("ensureValidE2EEIdentity drops mismatched local keys and registers Buffer keyData on rotation", async () => {
  const mid = `u${"a".repeat(32)}`;
  const wrongKey = createKeyPair();
  const serverLatest = createKeyPair();
  const base = new BaseClient({
    device: "IOSIPAD",
    fetch: async () => {
      throw new Error("unexpected network call");
    },
  });
  base.profile = { mid } as NonNullable<BaseClient["profile"]>;
  await base.storage.set(
    "e2eeKeys:6115157",
    JSON.stringify({
      keyId: 6115157,
      privKey: wrongKey.privKey.toString("base64"),
      pubKey: wrongKey.pubKey.toString("base64"),
    }),
  );

  let registeredKeyData: unknown;
  base.talk.getE2EEPublicKeys = async () =>
    [
      {
        version: 1,
        keyId: 6115157,
        keyData: serverLatest.pubKey,
        createdTime: Date.now(),
      },
    ] as never;
  base.talk.registerE2EEPublicKey = (async (args: { publicKey: { keyData: unknown } }) => {
    registeredKeyData = args.publicKey.keyData;
    return {
      version: 1,
      keyId: 6115200,
      keyData: args.publicKey.keyData,
      createdTime: Date.now(),
    };
  }) as never;

  const status = await ensureValidE2EEIdentity(base, { forceNewSenderKey: true });
  expect(status.ok).toBe(true);
  expect(status.keyId).toBe(6115200);
  expect(Buffer.isBuffer(registeredKeyData)).toBe(true);
  expect((registeredKeyData as Buffer).length).toBe(32);
  expect(await base.storage.get("e2eeKeys:6115157")).toBeUndefined();
});
