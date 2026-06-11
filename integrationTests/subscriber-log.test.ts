/**
 * Verifies the subscriberlog REST endpoint which logs subscriber events
 * and performs piracy detection based on access patterns.
 */
import { suite, test, before, after } from 'node:test';
import { strictEqual, ok } from 'node:assert/strict';
import { setupHarperWithFixture, teardownHarper, type ContextWithHarper } from '@harperfast/integration-testing';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
// harper's `exports` map only exposes ".", so 'harper/dist/bin/harper.js' is not
// resolvable. Resolve the CLI from the package's exported main entry instead.
const harperBinPath = resolve(dirname(require.resolve('harper')), 'bin/harper.js');

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtureDir = resolve(__dirname, '..');

function basicAuth(username: string, password: string): string {
  return 'Basic ' + Buffer.from(`${username}:${password}`).toString('base64');
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

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
    await setupHarperWithFixture(ctx, fixtureDir, { harperBinPath });
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

    strictEqual(res.status, 400, `expected 400 for missing subscriberId, got ${res.status}`);
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

  test('throttles (pirate=True, high_ip_count) when >4 unique client IPs hit the same content', async () => {
    const { admin, httpURL } = ctx.harper;
    const auth = basicAuth(admin.username, admin.password);
    const subscriberId = `ip-flood-${Date.now()}`;
    const contentname = 'flooded.mp4';

    // 5 distinct client IPs (> CLIENT_IPS = 4) within the 10s window.
    // The piracy check only counts records persisted strictly before the current
    // request (endTime = now-1), so let each write commit before the next request.
    let lastRes: Response | null = null;
    for (let i = 1; i <= 6; i++) {
      lastRes = await fetch(`${httpURL}/subscriberlog`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: auth },
        body: JSON.stringify(makeSubscriberEvent({ subscriberId, Contentname: contentname, clientIP: `${i}.${i}.${i}.${i}` })),
      });
      await sleep(50);
    }

    strictEqual(lastRes!.status, 200);
    strictEqual(lastRes!.headers.get('x-subscriber-pirate'), 'True', 'crossing the unique-IP limit should flag piracy');
    ok(
      (lastRes!.headers.get('x-subscriber-condition') ?? '').includes('high_ip_count'),
      `expected high_ip_count condition, got: ${lastRes!.headers.get('x-subscriber-condition')}`,
    );
  });

  test('throttles (pirate=True, multiple_sessions) when >1 session for same subscriber+IP', async () => {
    const { admin, httpURL } = ctx.harper;
    const auth = basicAuth(admin.username, admin.password);
    const subscriberId = `multi-session-${Date.now()}`;
    const clientIP = '203.0.113.7';

    let lastRes: Response | null = null;
    for (let i = 1; i <= 4; i++) {
      lastRes = await fetch(`${httpURL}/subscriberlog`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: auth },
        body: JSON.stringify(
          makeSubscriberEvent({ subscriberId, clientIP, clientsessionId: `session-${i}`, Contentname: 'series.mp4' }),
        ),
      });
      await sleep(50);
    }

    strictEqual(lastRes!.status, 200);
    strictEqual(lastRes!.headers.get('x-subscriber-pirate'), 'True', 'multiple sessions from one IP should flag piracy');
    ok(
      (lastRes!.headers.get('x-subscriber-condition') ?? '').includes('multiple_sessions'),
      `expected multiple_sessions condition, got: ${lastRes!.headers.get('x-subscriber-condition')}`,
    );
  });

  test('persists each event to the subscriber_log table (Harper DB state)', async () => {
    const { admin, httpURL } = ctx.harper;
    const auth = basicAuth(admin.username, admin.password);
    const subscriberId = `persist-${Date.now()}`;

    const writeRes = await fetch(`${httpURL}/subscriberlog`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: auth },
      body: JSON.stringify(makeSubscriberEvent({ subscriberId, Contentname: 'persisted.mp4', clientIP: '198.51.100.5' })),
    });
    strictEqual(writeRes.status, 200);
    await sleep(50);

    // Read it back through the exported subscriber_log REST table to confirm the
    // record was committed to Harper, not just held in memory.
    const queryRes = await fetch(`${httpURL}/subscriber_log/?contentname=persisted.mp4`, {
      headers: { Authorization: auth },
    });
    strictEqual(queryRes.status, 200);
    const rows = (await queryRes.json()) as Array<Record<string, unknown>>;
    ok(Array.isArray(rows), 'subscriber_log query should return an array');
    const match = rows.find((r) => Array.isArray(r.subscriberId) && r.subscriberId[0] === subscriberId);
    ok(match, `expected a persisted subscriber_log row for ${subscriberId}`);
    strictEqual(match!.clientIP, '198.51.100.5', 'persisted record should retain the client IP');
  });
});
