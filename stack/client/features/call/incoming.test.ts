import { assertEquals } from "@vyline/protocol/stack/assert";
import { parseIncomingCallRoutePayload, toAndromedaCallRoute } from "./incoming.ts";

Deno.test("incoming VoIP push requires host/token/UDP port", () => {
  assertEquals(
    parseIncomingCallRoutePayload({ voipHost: "203.0.113.1", voipPort: "9400" }, "VOIP_VOICE"),
    null,
  );
  assertEquals(
    parseIncomingCallRoutePayload(
      { voipHost: "203.0.113.1", voipToken: "token", voipPort: "0" },
      "VOIP_VOICE",
    ),
    null,
  );
});

Deno.test("incoming VoIP push maps verified LINE 26.13.0 keys", () => {
  const route = parseIncomingCallRoutePayload(
    {
      voipHost: "203.0.113.1",
      voipHost6: "2001:db8::1",
      voipToken: "secret-token",
      voipPort: "9400",
      voipTcpPort: 9401,
      voipFromZone: "JP",
      voipToZone: "JP",
      voipCommParam: "andromeda",
      voipSessionId: "session-1",
      voipTCPTunneling: "1",
      voipPublicKey: "public-key",
      voipCapabilities: '["opus","video"]',
      toMid: "u-local",
      switchableToVideo: "true",
    },
    "VOIP_VIDEO",
  );

  assertEquals(route, {
    callType: "VIDEO",
    token: "secret-token",
    address: "203.0.113.1",
    address6: "2001:db8::1",
    udpPort: 9400,
    tcpPort: 9401,
    fromZone: "JP",
    toZone: "JP",
    commParam: "andromeda",
    sessionId: "session-1",
    tcpTunneling: true,
    publicKey: "public-key",
    capabilities: ["opus", "video"],
    toMid: "u-local",
    switchableToVideo: true,
  });
});

Deno.test("incoming route adapter exposes only the Andromeda transport subset", () => {
  const parsed = parseIncomingCallRoutePayload(
    {
      voipHost: "203.0.113.2",
      voipToken: "secret-token",
      voipPort: 9500,
      voipCommParam: "andromeda",
      voipPublicKey: "do-not-guess-stnpk",
    },
    "VOIP_VOICE",
  );
  if (!parsed) throw new Error("expected route");

  const route = toAndromedaCallRoute(parsed) as unknown as Record<string, unknown>;
  assertEquals(route.voipAddress, "203.0.113.2");
  assertEquals(route.voipUdpPort, 9500);
  assertEquals(route.fromToken, "secret-token");
  assertEquals(route.commParam, "andromeda");
  assertEquals(route.stnpk, undefined);
  assertEquals(route.voipPublicKey, undefined);
});
