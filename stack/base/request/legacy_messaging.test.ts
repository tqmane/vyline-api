import { expect, test } from "bun:test";
import { BaseClient } from "../core/mod.ts";
import { Protocols, Thrift, type ParsedThrift } from "../thrift/mod.ts";
import { legacyMessagingHeaders } from "./legacy_messaging.ts";

const url = "https://legy-jp.line-apps.com/S4";

test("legacy headers follow RUIN's version/build while preserving the iOS device and OS", () => {
  for (const device of ["IOS", "IPAD", "IOSIPAD"]) {
    const headers = {
      "X-Line-Application": `${device}\t26.12.1\tiPhone OS\t18.2.1`,
      "X-Line-Application-Version": "26.12.1",
      "User-Agent": "iphoneapp.line/26.12.1 (iPhone; BuildVersion: 2026.1006.1718; CFNetwork/3860)",
      "x-line-access": "test-token",
    };
    expect(legacyMessagingHeaders(headers, url)).toEqual({
      "X-Line-Application": `${device}\t15.16.1\tiPhone OS\t18.2.1`,
      "X-Line-Application-Version": "15.16.1",
      "User-Agent": "iphoneapp.line/15.16.1 (iPhone; BuildVersion: 2025.926.1805; CFNetwork/3860)",
    });
    expect(headers["X-Line-Application-Version"]).toBe("26.12.1");
  }
});

test("legacy headers do not invent desktop/Android identities or escape LINE HTTPS", () => {
  for (const application of [
    "DESKTOPWIN\t26.3.0.3916\tWINDOWS\t10.0.0-11NT",
    "ANDROIDSECONDARY\t26.6.2\tAndroid OS\t16",
    "IOSIPAD\tinvalid\tiOS\t26.1",
  ]) {
    expect(legacyMessagingHeaders({ "x-line-application": application }, url)).toEqual({});
  }
  const headers = { "x-line-application": "IOSIPAD\t26.12.1\tiOS\t26.1" };
  for (const otherUrl of [
    "https://line-apps.com.evil.test/S4", "http://legy.line-apps.com/S4",
    "https://legy.line-apps.com:444/S4", "https://user@legy.line-apps.com/S4",
  ]) expect(legacyMessagingHeaders(headers, otherUrl)).toEqual({});
  expect(legacyMessagingHeaders({ ...headers, "X-Line-Application": headers["x-line-application"] }, url)).toEqual({});
});

test("mute metadata and opted-in unsend use legacy headers without affecting concurrent ordinary calls", async () => {
  const wire = new Thrift();
  const calls: Array<{ headers: Headers; body: ParsedThrift }> = [];
  const client = new BaseClient({
    device: "IOSIPAD",
    legy: { encrypted: false },
    fetch: async (request) => {
      const body = wire.readThrift(new Uint8Array(await request.arrayBuffer()), Protocols[4]);
      calls.push({ headers: request.headers, body });
      const result = body._info.fname === "sendMessage"
        ? [[12, 0, [[11, 4, "123"]]]]
        : body._info.fname === "silentlyUnsendMessage" ? [[12, 0, [[2, 1, true]]]] : [];
      return new Response(new Uint8Array(wire.writeThrift(result, body._info.fname, Protocols[4])));
    },
  });
  const initialHeaders = client.request.getHeader();
  client.e2ee.encryptE2EEMessage = async () => [Buffer.from("encrypted-content")];
  await Promise.all([
    client.talk.sendMessage({ to: "u-target", text: "quiet", e2ee: false,
      relatedMessageId: "reply-id", contentMetadata: { NOTIFICATION_DISABLED: "true", MENTION: "mentions" } }),
    client.talk.sendMessage({ to: "u-target", text: "encrypted", e2ee: true,
      contentMetadata: { NOTIFICATION_DISABLED: "true" } }),
    client.talk.sendMessage({ to: "u-target", text: "ordinary", e2ee: false, contentMetadata: undefined }),
    client.talk.unsendMessage({ messageId: "legacy", seq: 42 }, { legacy: true }),
    client.talk.unsendMessage({ messageId: "premium", seq: 43 }),
    client.talk.silentlyUnsendMessage({ messageId: "silent", reqSeq: 44 }),
  ]);
  expect(calls).toHaveLength(6);
  for (const { headers, body } of calls) {
    const legacy = body._info.fname === "sendMessage"
      ? body.data[2][18]?.NOTIFICATION_DISABLED === "true"
      : body._info.fname === "unsendMessage" && body.data[2] === "legacy";
    expect(headers.get("x-line-application")).toBe(`IOSIPAD\t${legacy ? "15.16.1" : "26.12.1"}\tiOS\t26.1`);
    expect(headers.get("user-agent")).toBe(`Line/${legacy ? "15.16.1" : "26.12.1"}`);
  }
  const quiet = calls.find(({ body }) => body.data[2]?.[10] === "quiet")!.body.data[2];
  expect(quiet[18]).toEqual({ NOTIFICATION_DISABLED: "true", MENTION: "mentions" });
  expect(quiet[21]).toBe("reply-id");
  const encrypted = calls.find(({ body }) => body.data[2]?.[20])!.body.data[2];
  expect(encrypted[10]).toBeUndefined();
  expect(encrypted[18]).toMatchObject({ NOTIFICATION_DISABLED: "true", e2eeVersion: "2" });
  expect(encrypted[20]).toEqual(["encrypted-content"]);
  expect(client.request.getHeader()).toEqual(initialHeaders);
});

test("legacy request headers survive token refresh and server rejections remain failures", async () => {
  const wire = new Thrift();
  const sent: Headers[] = [];
  const client = new BaseClient({
    device: "IOSIPAD", legy: { encrypted: false },
    fetch: async (request) => {
      sent.push(request.headers);
      return new Response(new Uint8Array(wire.writeThrift(
        [[12, 1, [[8, 1, sent.length === 1 ? 119 : 28]]]], "unsendMessage", Protocols[4],
      )));
    },
  });
  await client.storage.set("refreshToken", "mock-refresh");
  client.auth.tryRefreshToken = async () => { client.authToken = "new-opaque-token"; };
  await expect(client.talk.unsendMessage({ messageId: "123" }, { legacy: true })).rejects.toMatchObject({
    data: { code: "NOT_YOUR_MESSAGE" },
  });
  expect(sent).toHaveLength(2);
  expect(sent.every((headers) => headers.get("user-agent") === "Line/15.16.1")).toBe(true);
  expect(sent[1]!.get("x-line-access")).toBe("new-opaque-token");
});

test("encrypted LEGY outer headers use each request's effective version, including application-version", async () => {
  const requests: Request[] = [];
  const client = new BaseClient({
    device: "IOSIPAD", legy: { encrypted: true },
    fetch: async (request) => {
      requests.push(request);
      // The empty mock response intentionally cannot be decoded as an RPC.
      return new Response(null);
    },
  });
  client.authToken = "test-opaque-token";
  const getHeader = client.request.getHeader.bind(client.request);
  client.request.getHeader = () => ({ ...getHeader(), "x-line-application-version": "26.12.1" });
  const results = await Promise.allSettled([
    client.talk.unsendMessage({ messageId: "legacy" }, { legacy: true }),
    client.talk.getProfile(),
  ]);
  expect(results.every((result) => result.status === "rejected")).toBe(true);
  expect(requests).toHaveLength(2);
  for (const request of requests) {
    const version = request.headers.get("x-line-application")!.split("\t")[1];
    expect(request.url).toBe("https://gf.line.naver.jp/enc");
    expect(request.headers.get("user-agent")).toBe(`Line/${version}`);
    expect(request.headers.get("x-line-application-version")).toBe(version);
    expect(request.headers.has("x-line-access")).toBe(false);
  }
  expect(requests.map((r) => r.headers.get("x-line-application-version")).sort()).toEqual(["15.16.1", "26.12.1"]);
  expect(client.request.systemType).toBe("IOSIPAD\t26.12.1\tiOS\t26.1");
});

test("plain media uses the same legacy headers and mute metadata without changing the upload bytes", async () => {
  const requests: Request[] = [];
  const client = new BaseClient({
    device: "IOSIPAD",
    fetch: async (request) => {
      requests.push(request);
      return new Response(null, { headers: { "x-obs-oid": "object-id" } });
    },
  });
  client.authToken = "test-token";
  client.profile = { mid: "u-sender" } as never;
  for (const mute of [true, false]) {
    await client.obs.uploadObjTalk("u-target", "file", new Blob(["file-contents"]),
      undefined, "test.txt", undefined, undefined, undefined, undefined, mute);
  }
  expect(requests[0]!.headers.get("user-agent")).toBe("Line/15.16.1");
  expect(requests[0]!.headers.has("X-Talk-Meta")).toBe(true);
  expect(requests[1]!.headers.get("user-agent")).toBe("Line/26.12.1");
  expect(requests[1]!.headers.has("X-Talk-Meta")).toBe(false);
  expect(await requests[0]!.text()).toBe("file-contents");
  expect(await requests[1]!.text()).toBe("file-contents");
});
