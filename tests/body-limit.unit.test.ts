// 요청 본문 상한(감사 SOL-10): 선언 길이가 크면 읽지 않고, 선언이 없거나 거짓이어도 상한을 넘는 순간 읽기를 멈춘다.
import { describe, expect, it } from 'vitest';
import { readBodyLimited } from '../server/adapters.ts';
import { createAccountHandler } from '../server/account.ts';

const CHUNK = 1024;

/** 청크를 몇 번 꺼냈는지 세는 끝없는(또는 n 청크) 스트림. */
function countingStream(chunks = Infinity) {
  const state = { pulled: 0, cancelled: false };
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (state.pulled >= chunks) { controller.close(); return; }
      state.pulled++;
      controller.enqueue(new Uint8Array(CHUNK).fill(0x20));
    },
    cancel() { state.cancelled = true; },
  }, { highWaterMark: 0 });
  return { stream, state };
}

const streamRequest = (url: string, stream: ReadableStream<Uint8Array>, headers: Record<string, string> = {}) =>
  new Request(url, { method: 'POST', body: stream, headers, duplex: 'half' } as RequestInit);

describe('readBodyLimited', () => {
  it('stops pulling once the limit is passed and cancels the stream (no Content-Length)', async () => {
    const { stream, state } = countingStream();
    expect(await readBodyLimited(streamRequest('https://x/', stream), 8 * CHUNK)).toBeNull();
    expect(state.pulled).toBeLessThanOrEqual(9 + 1);
    expect(state.cancelled).toBe(true);
  });

  it('rejects a declared length over the limit without reading, and ignores a false small declaration', async () => {
    const big = countingStream();
    expect(await readBodyLimited(streamRequest('https://x/', big.stream, { 'content-length': String(1 << 30) }), 8 * CHUNK)).toBeNull();
    expect(big.state.pulled).toBe(0);
    const liar = countingStream();
    expect(await readBodyLimited(streamRequest('https://x/', liar.stream, { 'content-length': '10' }), 8 * CHUNK)).toBeNull();
    expect(liar.state.pulled).toBeLessThanOrEqual(10);
    const nan = countingStream(1);
    expect(await readBodyLimited(streamRequest('https://x/', nan.stream, { 'content-length': 'abc' }), 8 * CHUNK)).toBeNull();
  });

  it('accepts exactly the limit and returns the bytes', async () => {
    const { stream } = countingStream(8);
    const out = await readBodyLimited(streamRequest('https://x/', stream), 8 * CHUNK);
    expect(out?.byteLength).toBe(8 * CHUNK);
  });
});

describe('handlers use the bounded reader', () => {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const token = `${b64({ alg: 'ES256' })}.${b64({ sub: 'u' })}.sig`;

  it('community-account refuses an oversized streamed body before Auth is asked', async () => {
    let userCalls = 0;
    const handler = createAccountHandler({
      enabled: true, jwtIssuer: null,
      getUser: async () => { userCalls++; return null; },
      rpc: async () => ({ allowed: true }),
    } as never);
    const { stream, state } = countingStream();
    const res = await handler(streamRequest('https://p.supabase.co/functions/v1/community-account/status', stream,
      { 'content-type': 'application/json', authorization: `Bearer ${token}` }));
    expect(res.status).toBe(400);
    expect((await res.json()).error.code).toBe('invalid_request');
    expect(state.pulled).toBeLessThanOrEqual(8 + 2); // 8 KiB 상한
    expect(userCalls).toBe(0);
  });
});
