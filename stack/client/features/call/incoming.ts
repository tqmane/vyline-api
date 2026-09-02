import type * as LINETypes from "@vyline/line-types";

export type IncomingVoipPushType = "VOIP_VOICE" | "VOIP_VIDEO";

/**
 * Rich incoming-call route carried by LINE's VoIP push path.
 *
 * This is intentionally separate from NOTIFIED_RECEIVED_CALL. The Talk
 * operation only identifies the affected chat; it does not carry the media
 * route required to answer a call.
 */
export interface IncomingCallRoutePayload {
  callType: "AUDIO" | "VIDEO";
  token: string;
  address: string;
  address6?: string;
  udpPort: number;
  tcpPort?: number;
  fromZone?: string;
  toZone?: string;
  commParam?: string;
  sessionId?: string;
  tcpTunneling?: boolean;
  publicKey?: string;
  toMid?: string;
  switchableToVideo?: boolean;
  capabilities?: string[];
}

function text(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed ? trimmed : undefined;
}

function port(value: unknown): number | undefined {
  const n = typeof value === "number" ? value : typeof value === "string" ? Number(value) : NaN;
  if (!Number.isInteger(n) || n < 1 || n > 65535) return undefined;
  return n;
}

function bool(value: unknown): boolean | undefined {
  if (typeof value === "boolean") return value;
  if (typeof value !== "string") return undefined;
  if (/^(?:1|true)$/i.test(value)) return true;
  if (/^(?:0|false)$/i.test(value)) return false;
  return undefined;
}

function capabilities(value: unknown): string[] | undefined {
  if (Array.isArray(value)) {
    const values = value.map(text).filter((v): v is string => Boolean(v));
    return values.length ? values : undefined;
  }
  const raw = text(value);
  if (!raw) return undefined;
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (Array.isArray(parsed)) {
      const values = parsed.map(text).filter((v): v is string => Boolean(v));
      return values.length ? values : undefined;
    }
  } catch {
    // Some push implementations expose a comma-separated capability string.
  }
  const values = raw
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean);
  return values.length ? values : undefined;
}

/**
 * Parse the Android-style VoIP push keys observed in LINE 26.13.0.
 * Returns null unless the minimum Andromeda route (host/token/UDP port) is
 * present. The raw payload is deliberately not retained because it contains a
 * bearer-like VoIP token.
 */
export function parseIncomingCallRoutePayload(
  payload: Record<string, unknown>,
  pushType: IncomingVoipPushType,
): IncomingCallRoutePayload | null {
  const address = text(payload.voipHost);
  const token = text(payload.voipToken);
  const udpPort = port(payload.voipPort);
  if (!address || !token || !udpPort) return null;

  return {
    callType: pushType === "VOIP_VIDEO" ? "VIDEO" : "AUDIO",
    token,
    address,
    address6: text(payload.voipHost6),
    udpPort,
    tcpPort: port(payload.voipTcpPort),
    fromZone: text(payload.voipFromZone),
    toZone: text(payload.voipToZone),
    commParam: text(payload.voipCommParam),
    sessionId: text(payload.voipSessionId),
    tcpTunneling: bool(payload.voipTCPTunneling),
    publicKey: text(payload.voipPublicKey),
    capabilities: capabilities(payload.voipCapabilities),
    toMid: text(payload.toMid),
    switchableToVideo: bool(payload.switchableToVideo),
  };
}

/**
 * Adapt the verified subset of the incoming push route to the existing
 * Andromeda transport. Unknown CallRoute fields are intentionally left unset;
 * the incoming SIP transport only consumes the endpoint credentials below.
 */
export function toAndromedaCallRoute(route: IncomingCallRoutePayload): LINETypes.CallRoute {
  return {
    fromToken: route.token,
    voipAddress: route.address,
    voipAddress6: route.address6 ?? "",
    voipUdpPort: route.udpPort,
    voipTcpPort: route.tcpPort ?? 0,
    fromZone: route.fromZone ?? "",
    toZone: route.toZone ?? "",
    toMid: route.toMid ?? "",
    commParam: route.commParam ?? "",
    stid: route.sessionId ?? "",
    tunneling: route.tcpTunneling ? "1" : "0",
    switchableToVideo: route.switchableToVideo ?? route.callType === "VIDEO",
    capabilities: route.capabilities ?? [],
  } as LINETypes.CallRoute;
}
