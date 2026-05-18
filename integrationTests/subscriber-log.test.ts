/**
 * Verifies the subscriberlog REST endpoint which logs subscriber events
 * and performs piracy detection based on access patterns.
 */
import { suite, test, before, after } from 'node:test';
import { strictEqual, ok } from 'node:assert/strict';
import { setupHarperWithFixture, teardownHarper, type ContextWithHarper } from '@harperfast/integration-testing';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtureDir = resolve(__dirname, '..');

function basicAuth(username: string, password: string): string {
  return 'Basic ' + Buffer.from(`${username}:${password}`).toString('base64');
}

function makeSubscriberEvent(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    subscriberId: `sub-${Date.now()}-${Math.random()}`,
    clientsessionId: 'session-abc-123',
    clientIP: '192.168.1.100',
    edgeIP: '10.0.0.1',
    Contentname: 'movie.mp4',
    useragent: 'TestAgent/1.0',
    Host: 'example.com',
    Path: '/video/movie.mp4',
    clientLocation: 'US',
    ...overrides,
  };
}

suite('subscriberlog POST', (ctx: ContextWithHarper) => {
  before(async () => {
    await setupHarperWithFixture(ctx, fixtureDir);
  });

  after(async () => {
    await teardownHarper(ctx);
  });

  test('returns 200 and piracy response headers for a valid request', async () => {
    const { admin, httpURL } = ctx.harper;
    const auth = basicAuth(admin.username, admin.password);

    const res = await fetch(`${httpURL}/subscriberlog`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: auth },
      body: JSON.stringify(makeSubscriberEvent()),
    });

    strictEqual(res.status, 200);
    const pirateHeader = res.headers.get('x-subscriber-pirate');
    const blacklistHeader = res.headers.get('x-subscriber-blacklist');
    ok(
      pirateHeader === 'True' || pirateHeader === 'False',
      `X-subscriber-pirate header should be 'True' or 'False', got: ${pirateHeader}`,
    );
    strictEqual(blacklistHeader, 'False', 'X-subscriber-blacklist should be False');
  });

  test('returns an error when subscriberId is missing', async () => {
    const { admin, httpURL } = ctx.harper;
    const auth = basicAuth(admin.username, admin.password);

    const res = await fetch(`${httpURL}/subscriberlog`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: auth },
      body: JSON.stringify({
        clientsessionId: 'session-123',
        clientIP: '192.168.1.1',
        Contentname: 'video.mp4',
      }),
    });

    ok(res.status >= 400, `expected error status for missing subscriberId, got ${res.status}`);
  });

  test('X-subscriber-pirate is False for a single legitimate request', async () => {
    const { admin, httpURL } = ctx.harper;
    const auth = basicAuth(admin.username, admin.password);
    const uniqueId = `unique-sub-${Date.now()}`;

    const res = await fetch(`${httpURL}/subscriberlog`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: auth },
      body: JSON.stringify(makeSubscriberEvent({ subscriberId: uniqueId })),
    });

    strictEqual(res.status, 200);
    const pirateHeader = res.headers.get('x-subscriber-pirate');
    strictEqual(pirateHeader, 'False', 'A single request should not trigger piracy detection');
  });

  test('X-subscriber-pirate is False for a few requests from the same subscriber', async () => {
    const { admin, httpURL } = ctx.harper;
    const auth = basicAuth(admin.username, admin.password);
    const subscriberId = `normal-sub-${Date.now()}`;

    let lastRes: Response | null = null;
    for (let i = 0; i < 3; i++) {
      lastRes = await fetch(`${httpURL}/subscriberlog`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: auth },
        body: JSON.stringify(makeSubscriberEvent({ subscriberId, clientIP: '10.0.0.1' })),
      });
    }

    strictEqual(lastRes!.status, 200);
    const pirateHeader = lastRes!.headers.get('x-subscriber-pirate');
    strictEqual(pirateHeader, 'False', 'A few normal requests should not trigger piracy detection');
  });
});
