import { describe, expect, test } from "bun:test";
import dgram from "node:dgram";
import { Buffer } from "node:buffer";
import { AndromedaTransport } from "./andromeda.js";
import { buildSip, parseSip } from "./sip.js";

// `CallSession.received()` terminates only when the transport's read loop ends,
// and the backend treats that termination as a remote hangup. These cases pin that
// contract for the SIP transport, whose handshake waiter queue is empty afterwards.

type Invited = { sip: ReturnType<typeof parseSip>; rinfo: dgram.RemoteInfo };

async function spawnMockUas() {
  const sock = dgram.createSocket("udp4");
  const exchanges: string[] = [];
  let phase: "challenge" | "ok" | "invited" | "acked" = "challenge";
  let answered: Invited | undefined;
  sock.on("message", (buf, rinfo) => {
    const sip = parseSip(new Uint8Array(buf));
    exchanges.push(sip.startLine);
    if (sip.startLine.startsWith("REGISTER") && phase === "challenge") {
      sock.send(
        Buffer.from(
          buildSip({
            startLine: "SIP/2.0 401 Unauthorized",
            headers: {
              Via: sip.headers["Via"],
              From: sip.headers["From"],
              To: `${sip.headers["To"]};tag=mock`,
              "Call-ID": sip.headers["Call-ID"],
              CSeq: sip.headers["CSeq"],
              "WWW-Authenticate": `Digest realm="mock", nonce="n1", qop="auth", algorithm=MD5`,
              "Content-Length": "0",
            },
            body: "",
          }),
        ),
        rinfo.port,
        rinfo.address,
      );
      phase = "ok";
      return;
    }
    if (sip.startLine.startsWith("REGISTER")) {
      sock.send(
        Buffer.from(
          buildSip({
            startLine: "SIP/2.0 200 OK",
            headers: {
              Via: sip.headers["Via"],
              From: sip.headers["From"],
              To: `${sip.headers["To"]};tag=mock`,
              "Call-ID": sip.headers["Call-ID"],
              CSeq: sip.headers["CSeq"],
              "Content-Length": "0",
            },
            body: "",
          }),
        ),
        rinfo.port,
        rinfo.address,
      );
      phase = "invited";
      return;
    }
    if (!sip.startLine.startsWith("INVITE")) return;
    answered = { sip, rinfo };
    const keyB64 = btoa(String.fromCharCode(...Array.from({ length: 30 }, (_, i) => (i + 99) & 0xff)));
    const answer = [
      "v=0",
      "o=mock 1 1 IN IP4 127.0.0.1",
      "s=-",
      "c=IN IP4 127.0.0.1",
      "t=0 0",
      "m=audio 5004 RTP/SAVP 96",
      "a=rtpmap:96 opus/48000/2",
      `a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:${keyB64}`,
      "a=sendrecv",
      "",
    ].join("\r\n");
    sock.send(
      Buffer.from(
        buildSip({
          startLine: "SIP/2.0 200 OK",
          headers: {
            Via: sip.headers["Via"],
            From: sip.headers["From"],
            To: `${sip.headers["To"]};tag=callee`,
            "Call-ID": sip.headers["Call-ID"],
            CSeq: sip.headers["CSeq"],
            "Content-Type": "application/sdp",
            "Content-Length": String(answer.length),
          },
          body: answer,
        }),
      ),
      rinfo.port,
      rinfo.address,
    );
    phase = "acked";
  });
  const port = await new Promise<number>((res) => {
    sock.bind({ address: "127.0.0.1", port: 0 }, () => res((sock.address() as { port: number }).port));
  });
  return {
    host: "127.0.0.1",
    port,
    exchanges,
    stop: () => new Promise<void>((res) => sock.close(() => res())),
    /** Peer-initiated hangup: the only SIP request that arrives after setup. */
    hangup() {
      if (!answered) throw new Error("INVITE was never answered");
      const { sip: invite, rinfo } = answered;
      sock.send(
        Buffer.from(
          buildSip({
            startLine: "BYE sip:u-test-mid@invalid SIP/2.0",
            headers: {
              Via: "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-mockbye",
              "Max-Forwards": "70",
              From: `${invite.headers["To"]};tag=callee`,
              To: invite.headers["From"] ?? "",
              "Call-ID": invite.headers["Call-ID"],
              CSeq: "2 BYE",
              "User-Agent": "MockUAS/1.0",
              "Content-Length": "0",
            },
            body: "",
          }),
        ),
        rinfo.port,
        rinfo.address,
      );
    },
  };
}

async function connected(mock: Awaited<ReturnType<typeof spawnMockUas>>) {
  const transport = new AndromedaTransport({ localMid: "u-test-mid" });
  await transport.connect({
    route: { voipAddress: mock.host, voipUdpPort: mock.port, fromToken: "secret-pw" } as never,
  });
  await transport.invite({ to: "u-peer" });
  return transport;
}

const settled = <T>(work: Promise<T>, ms: number) =>
  Promise.race([
    work.then((value) => ({ value })),
    new Promise<{ value: null }>((res) => setTimeout(() => res({ value: null }), ms)),
  ]);

describe("AndromedaTransport hangup detection", () => {
  test("a peer BYE ends the media read loop and is acknowledged", async () => {
    const mock = await spawnMockUas();
    const transport = await connected(mock);
    try {
      const iterator = transport.receive()[Symbol.asyncIterator]();
      // Let the loop park on its RTP waiter so releasing it is what ends the loop.
      await Bun.sleep(60);

      mock.hangup();
      expect(await settled(iterator.next(), 4000)).toEqual({ value: { done: true, value: undefined } });
      // The peer must be told the hangup was accepted so it stops retransmitting.
      const deadline = Date.now() + 4000;
      while (Date.now() < deadline && !mock.exchanges.includes("SIP/2.0 200 OK")) await Bun.sleep(25);
      expect(mock.exchanges).toContain("SIP/2.0 200 OK");
    } finally {
      await transport.close().catch(() => undefined);
      await mock.stop();
    }
  }, 20_000);

  test("closing the transport releases a parked read loop", async () => {
    const mock = await spawnMockUas();
    const transport = await connected(mock);
    try {
      const iterator = transport.receive()[Symbol.asyncIterator]();
      await Bun.sleep(60);
      await transport.close();
      expect(await settled(iterator.next(), 4000)).toEqual({ value: { done: true, value: undefined } });
    } finally {
      await mock.stop();
    }
  }, 20_000);

  test("the handshake still completes and the ACK is sent", async () => {
    const mock = await spawnMockUas();
    const transport = await connected(mock);
    try {
      expect(mock.exchanges.map((line) => line.split(" ")[0])).toEqual(["REGISTER", "REGISTER", "INVITE"]);
      await Bun.sleep(80);
      expect(mock.exchanges.map((line) => line.split(" ")[0])).toEqual(["REGISTER", "REGISTER", "INVITE", "ACK"]);
    } finally {
      await transport.close().catch(() => undefined);
      await mock.stop();
    }
  }, 20_000);
});
