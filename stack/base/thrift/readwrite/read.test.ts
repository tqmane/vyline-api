import { expect, test } from "bun:test";
import { TBinaryProtocol, TCompactProtocol, TFramedTransport, Thrift } from "thrift";
import { readThriftStruct } from "./read.ts";

test("Thrift reads signed scalar values without dropping BYTE or I16 fields", () => {
  for (const Protocol of [TBinaryProtocol, TCompactProtocol]) {
    const chunks: Buffer[] = [];
    const transport = new TFramedTransport(undefined, (chunk: Buffer) => chunks.push(chunk));
    const protocol = new Protocol(transport);
    protocol.writeStructBegin("");
    protocol.writeFieldBegin("", Thrift.Type.BYTE, 1);
    protocol.writeByte(-7);
    protocol.writeFieldEnd();
    protocol.writeFieldBegin("", Thrift.Type.I16, 2);
    protocol.writeI16(-1234);
    protocol.writeFieldEnd();
    for (const [id, value] of [
      [3, -5],
      [4, Number.MIN_SAFE_INTEGER],
    ] as const) {
      protocol.writeFieldBegin("", Thrift.Type.I64, id);
      protocol.writeI64(value);
      protocol.writeFieldEnd();
    }
    protocol.writeFieldStop();
    protocol.writeStructEnd();
    transport.flush();
    // TFramedTransport flush prefixes the four-byte frame length.
    expect(readThriftStruct(Buffer.concat(chunks).subarray(4), Protocol)).toEqual({
      1: -7,
      2: -1234,
      3: -5,
      4: Number.MIN_SAFE_INTEGER,
    });
  }
});

test("standard Thrift rejects MoreCompact extensions instead of reading them as strings", () => {
  for (const type of [16, 17]) {
    expect(() => readThriftStruct(Buffer.from([type, 0, 1, 0]), TBinaryProtocol)).toThrow(
      `Unsupported Thrift field type: ${type}`,
    );
  }
});
