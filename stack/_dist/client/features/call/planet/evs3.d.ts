export declare const MAX_VIDEO_FRAME_BYTES: number;
export interface EncodedVideoFrame {
    /** A complete AVCC access unit, including in-band SPS/PPS on key pictures. */
    data: Uint8Array;
    key: boolean;
    /** Unsigned 90 kHz RTP timestamp. */
    timestamp: number;
}
export declare function validateAvcc(data: Uint8Array): void;
export declare function packetizeEvs3(data: Uint8Array, key: boolean, pictureId: number, fragmentBytes?: number): Uint8Array[];
export declare function parseEvs3(payload: Uint8Array): {
    pictureId: number;
    begin: boolean;
    end: boolean;
    key: boolean;
    rotation: number;
    offset: number;
};
interface VideoRtpPacket {
    payload: Uint8Array;
    seq: number;
    timestamp: number;
    ssrc: number;
    marker: boolean;
}
export declare class Evs3Assembler {
    #private;
    clear(): void;
    push(packet: VideoRtpPacket, now?: number): EncodedVideoFrame | undefined;
}
export {};
