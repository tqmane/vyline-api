import type * as LINETypes from "@vyline/line-types";
export type IncomingVoipPushType = "VOIP_VOICE" | "VOIP_VIDEO";
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
export declare function parseIncomingCallRoutePayload(payload: Record<string, unknown>, pushType: IncomingVoipPushType): IncomingCallRoutePayload | null;
export declare function toAndromedaCallRoute(route: IncomingCallRoutePayload): LINETypes.CallRoute;
