import { test, describe, beforeEach, afterEach } from 'node:test';
import * as assert from 'node:assert';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { SeatlingClient } from '../src/client';
import { HWIDCollector } from '../src/hwid';
import { CapturedRequest, ThreadedMockServer } from './helpers/mock-server';

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

describe('SeatlingClient Network Protocol & Server Error Handling', () => {
  let tmpDir: string;
  let workspacePublicKeyBase64: string;
  let workspacePrivKeyDerHex: string;
  let mockServer: ThreadedMockServer;
  let serverBaseUrl: string;

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'seatling-node-net-test-'));

    // Generate workspace Ed25519 keypair
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    workspacePublicKeyBase64 = spkiDer.subarray(ED25519_SPKI_PREFIX.length).toString('base64');
    workspacePrivKeyDerHex = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex');

    mockServer = new ThreadedMockServer();
    serverBaseUrl = await mockServer.start();
  });

  afterEach(async () => {
    await mockServer.stop();
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // Ignored
    }
  });

  test('successfully activates license over HTTP with valid Proof-of-Possession JWT', async () => {
    const now = Math.floor(Date.now() / 1000);
    mockServer.setLicenseSignRule('/v1/licenses/activate', 'ws_test_key_2026', workspacePrivKeyDerHex, {
      iss: 'seatling',
      sub: 'SEAT-ABCD-1234',
      aud: 'ws_net',
      product_id: 'prod_net',
      seat_id: 'seat_net_01',
      masked_key: 'SEAT-****-1234',
      buyer_email: 'buyer@example.com',
      hwid: HWIDCollector.getHWID(),
      app_version: '1.0.0',
      iat: now,
      nbf: now,
      exp: now + 14 * 86400,
      offline_grace_days: 14,
      status: 'active',
      entitlements: { pro_feature: true, max_streams: 8 },
    });

    const client = new SeatlingClient({
      workspaceId: 'ws_net',
      productId: 'prod_net',
      publicKeys: { ws_test_key_2026: workspacePublicKeyBase64 },
      appVersion: '1.0.0',
      apiBaseUrl: serverBaseUrl,
      storageDir: tmpDir,
    });

    const initStatus = client.initialize();
    assert.strictEqual(initStatus.status, 'NOT_ACTIVATED');
    assert.strictEqual(client.isAuthorized(), false);

    const activateRes = await client.activate('SEAT-ABCD-1234');
    assert.strictEqual(activateRes.success, true);
    assert.strictEqual(activateRes.status, 'OK');
    assert.strictEqual(activateRes.seatId, 'seat_net_01');
    assert.ok(activateRes.token);

    // Verify PoP JWT was transmitted to server
    const captured = await mockServer.getCaptured();
    assert.strictEqual(captured.length, 1);
    const popJwt = captured[0].body.token;
    assert.ok(popJwt);
    const popParts = popJwt.split('.');
    const popClaims = JSON.parse(Buffer.from(popParts[1], 'base64url').toString('utf8'));
    assert.strictEqual(popClaims.sub, 'SEAT-ABCD-1234');
    assert.strictEqual(popClaims.app_version, '1.0.0');

    // Client cache and local disk storage verification
    assert.strictEqual(client.isAuthorized(), true);
    assert.strictEqual(client.getEntitlement('pro_feature', false), true);
    assert.strictEqual(client.getEntitlement('max_streams', 1), 8);
    assert.ok(fs.existsSync(path.join(tmpDir, 'lease.seatling')));

    client.shutdown();
  });

  test('handles HTTP 403 VERSION_NOT_ENTITLED and sets VERSION_CEILING_EXCEEDED', async () => {
    mockServer.setStaticRule('/v1/licenses/activate', 403, {
      type: 'https://api.seatling.com/errors/version-not-entitled',
      status: 403,
      title: 'Version Not Entitled',
      detail: 'License is not entitled to run app version 1.0.0',
      portal_url: 'https://portal.seatling.com/upgrade',
    });

    const client = new SeatlingClient({
      workspaceId: 'ws_net',
      productId: 'prod_net',
      publicKeys: { ws_test_key_2026: workspacePublicKeyBase64 },
      appVersion: '1.0.0',
      apiBaseUrl: serverBaseUrl,
      storageDir: tmpDir,
    });

    const activateRes = await client.activate('SEAT-OLD-VERSION');
    assert.strictEqual(activateRes.success, false);
    assert.strictEqual(activateRes.status, 'VERSION_CEILING_EXCEEDED');
    assert.strictEqual(activateRes.portalUrl, 'https://portal.seatling.com/upgrade');
    assert.match(activateRes.message, /not entitled/);
    assert.strictEqual(client.isAuthorized(), false);

    client.shutdown();
  });

  test('handles HTTP 403 KEY_REVOKED_UPDATE_REQUIRED', async () => {
    mockServer.setStaticRule('/v1/licenses/activate', 403, {
      type: 'https://api.seatling.com/errors/key-revoked',
      status: 403,
      title: 'Workspace Key Revoked',
      detail: 'Workspace signing key was revoked. App update required.',
      portal_url: 'https://portal.seatling.com/update',
    });

    const client = new SeatlingClient({
      workspaceId: 'ws_net',
      productId: 'prod_net',
      publicKeys: { ws_test_key_2026: workspacePublicKeyBase64 },
      appVersion: '1.0.0',
      apiBaseUrl: serverBaseUrl,
      storageDir: tmpDir,
    });

    const activateRes = await client.activate('SEAT-REVOKED');
    assert.strictEqual(activateRes.success, false);
    assert.strictEqual(activateRes.status, 'KEY_REVOKED_UPDATE_REQUIRED');
    assert.strictEqual(activateRes.portalUrl, 'https://portal.seatling.com/update');

    client.shutdown();
  });

  test('handles HTTP 403 SEATS_EXHAUSTED with quota limits and buyer email hint', async () => {
    mockServer.setStaticRule('/v1/licenses/activate', 403, {
      type: 'https://api.seatling.com/errors/seats-exhausted',
      status: 403,
      title: 'Seats Exhausted',
      detail: 'Seat limit reached for this license.',
      portal_url: 'https://portal.seatling.com/seats',
      buyer_email: 'b***@example.com',
      seats_active: 3,
      seat_limit: 3,
    });

    const client = new SeatlingClient({
      workspaceId: 'ws_net',
      productId: 'prod_net',
      publicKeys: { ws_test_key_2026: workspacePublicKeyBase64 },
      appVersion: '1.0.0',
      apiBaseUrl: serverBaseUrl,
      storageDir: tmpDir,
    });

    const activateRes = await client.activate('SEAT-LIMIT-REACHED');
    assert.strictEqual(activateRes.success, false);
    assert.strictEqual(activateRes.status, 'SEATS_EXHAUSTED');
    assert.strictEqual(activateRes.portalUrl, 'https://portal.seatling.com/seats');
    assert.strictEqual(activateRes.buyerEmail, 'b***@example.com');
    assert.strictEqual(activateRes.seatsActive, 3);
    assert.strictEqual(activateRes.seatLimit, 3);

    client.shutdown();
  });

  test('handles HTTP 409 REQUIRES_PORTAL_DEACTIVATION on rotation quota exceeded', async () => {
    mockServer.setStaticRule('/v1/licenses/activate', 409, {
      type: 'https://api.seatling.com/errors/requires-portal-deactivation',
      status: 409,
      title: 'Requires Customer Portal Deactivation',
      detail: 'Key rotation quota exceeded. Deactivate in portal first.',
      portal_url: 'https://portal.seatling.com/manage',
    });

    const client = new SeatlingClient({
      workspaceId: 'ws_net',
      productId: 'prod_net',
      publicKeys: { ws_test_key_2026: workspacePublicKeyBase64 },
      appVersion: '1.0.0',
      apiBaseUrl: serverBaseUrl,
      storageDir: tmpDir,
    });

    const activateRes = await client.activate('SEAT-QUOTA-EXCEEDED');
    assert.strictEqual(activateRes.success, false);
    assert.strictEqual(activateRes.status, 'REQUIRES_PORTAL_DEACTIVATION');
    assert.strictEqual(activateRes.portalUrl, 'https://portal.seatling.com/manage');

    client.shutdown();
  });

  test('executes 1-RTT mutual-challenge heartbeat and updates grace duration and entitlements', async () => {
    const now = Math.floor(Date.now() / 1000);

    // Rule 1: Activation
    mockServer.setLicenseSignRule('/v1/licenses/activate', 'ws_test_key_2026', workspacePrivKeyDerHex, {
      iss: 'seatling',
      sub: 'SEAT-HB-001',
      aud: 'ws_net',
      product_id: 'prod_net',
      seat_id: 'seat_hb_01',
      hwid: HWIDCollector.getHWID(),
      app_version: '1.0.0',
      iat: now,
      nbf: now,
      exp: now + 14 * 86400,
      offline_grace_days: 14,
      status: 'active',
      entitlements: { max_streams: 4 },
    });

    // Rule 2: Heartbeat ack with echoed nonce and updated entitlements
    mockServer.setHeartbeatAckRule('/v1/licenses/heartbeat', 'ws_test_key_2026', workspacePrivKeyDerHex, {
      iss: 'seatling',
      sub: 'SEAT-HB-001',
      aud: 'ws_net',
      product_id: 'prod_net',
      seat_id: 'seat_hb_01',
      status: 'active',
      iat: now,
      exp: now + 14 * 86400,
      entitlements: { max_streams: 32, pro_dsp: true },
    });

    const client = new SeatlingClient({
      workspaceId: 'ws_net',
      productId: 'prod_net',
      publicKeys: { ws_test_key_2026: workspacePublicKeyBase64 },
      appVersion: '1.0.0',
      apiBaseUrl: serverBaseUrl,
      storageDir: tmpDir,
    });

    await client.activate('SEAT-HB-001');
    assert.strictEqual(client.getEntitlement('max_streams', 1), 4);

    const hbStatus = await client.heartbeatNow();
    assert.strictEqual(hbStatus.status, 'OK');
    assert.strictEqual(hbStatus.isAuthorized, true);

    // Verify updated entitlements
    assert.strictEqual(client.getEntitlement('max_streams', 1), 32);
    assert.strictEqual(client.getEntitlement('pro_dsp', false), true);

    client.shutdown();
  });

  test('rejects heartbeat acknowledgment when echoed nonce does not match challenge jti', async () => {
    const now = Math.floor(Date.now() / 1000);

    mockServer.setLicenseSignRule('/v1/licenses/activate', 'ws_test_key_2026', workspacePrivKeyDerHex, {
      iss: 'seatling',
      sub: 'SEAT-NONCE-TEST',
      aud: 'ws_net',
      product_id: 'prod_net',
      seat_id: 'seat_nonce_01',
      hwid: HWIDCollector.getHWID(),
      app_version: '1.0.0',
      iat: now,
      nbf: now,
      exp: now + 14 * 86400,
      offline_grace_days: 14,
      status: 'active',
      entitlements: { max_streams: 4 },
    });

    // Return wrong nonce (simulating replay of an older ack)
    mockServer.setHeartbeatAckRule('/v1/licenses/heartbeat', 'ws_test_key_2026', workspacePrivKeyDerHex, {
      iss: 'seatling',
      sub: 'SEAT-NONCE-TEST',
      aud: 'ws_net',
      product_id: 'prod_net',
      seat_id: 'seat_nonce_01',
      status: 'active',
      iat: now,
      exp: now + 14 * 86400,
      entitlements: { max_streams: 999 },
    }, { overrideNonce: 'wrong_stale_nonce_replay' });

    const client = new SeatlingClient({
      workspaceId: 'ws_net',
      productId: 'prod_net',
      publicKeys: { ws_test_key_2026: workspacePublicKeyBase64 },
      appVersion: '1.0.0',
      apiBaseUrl: serverBaseUrl,
      storageDir: tmpDir,
    });

    await client.activate('SEAT-NONCE-TEST');
    assert.strictEqual(client.getEntitlement('max_streams', 1), 4);

    await client.heartbeatNow();

    // Mismatched nonce should be rejected; entitlements must remain unpolluted
    assert.strictEqual(client.getEntitlement('max_streams', 1), 4);

    client.shutdown();
  });

  test('immediately revokes authorization when heartbeat ack reports status locked', async () => {
    const now = Math.floor(Date.now() / 1000);

    mockServer.setLicenseSignRule('/v1/licenses/activate', 'ws_test_key_2026', workspacePrivKeyDerHex, {
      iss: 'seatling',
      sub: 'SEAT-LOCK-TEST',
      aud: 'ws_net',
      product_id: 'prod_net',
      seat_id: 'seat_lock_01',
      hwid: HWIDCollector.getHWID(),
      app_version: '1.0.0',
      iat: now,
      nbf: now,
      exp: now + 14 * 86400,
      offline_grace_days: 14,
      status: 'active',
      entitlements: {},
    });

    mockServer.setHeartbeatAckRule('/v1/licenses/heartbeat', 'ws_test_key_2026', workspacePrivKeyDerHex, {
      iss: 'seatling',
      sub: 'SEAT-LOCK-TEST',
      aud: 'ws_net',
      product_id: 'prod_net',
      seat_id: 'seat_lock_01',
      status: 'locked',
      iat: now,
      exp: now + 14 * 86400,
      entitlements: {},
    }, { extraResponseFields: { portal_url: 'https://portal.seatling.com/locked' } });

    const client = new SeatlingClient({
      workspaceId: 'ws_net',
      productId: 'prod_net',
      publicKeys: { ws_test_key_2026: workspacePublicKeyBase64 },
      appVersion: '1.0.0',
      apiBaseUrl: serverBaseUrl,
      storageDir: tmpDir,
    });

    await client.activate('SEAT-LOCK-TEST');
    assert.strictEqual(client.isAuthorized(), true);

    const hbStatus = await client.heartbeatNow();
    assert.strictEqual(hbStatus.status, 'REQUIRES_PORTAL_DEACTIVATION');
    assert.strictEqual(client.isAuthorized(), false);
    assert.strictEqual(client.isValid(), false);

    client.shutdown();
  });

  test('preserves offline grace when heartbeat fails due to server error or network down', async () => {
    const now = Math.floor(Date.now() / 1000);

    mockServer.setLicenseSignRule('/v1/licenses/activate', 'ws_test_key_2026', workspacePrivKeyDerHex, {
      iss: 'seatling',
      sub: 'SEAT-OFFLINE-TEST',
      aud: 'ws_net',
      product_id: 'prod_net',
      seat_id: 'seat_off_01',
      hwid: HWIDCollector.getHWID(),
      app_version: '1.0.0',
      iat: now,
      nbf: now,
      exp: now + 14 * 86400,
      offline_grace_days: 14,
      status: 'active',
      entitlements: {},
    });

    // Heartbeat returns HTTP 500
    mockServer.setStaticRule('/v1/licenses/heartbeat', 500, { error: 'internal server error' });

    const client = new SeatlingClient({
      workspaceId: 'ws_net',
      productId: 'prod_net',
      publicKeys: { ws_test_key_2026: workspacePublicKeyBase64 },
      appVersion: '1.0.0',
      apiBaseUrl: serverBaseUrl,
      storageDir: tmpDir,
    });

    await client.activate('SEAT-OFFLINE-TEST');
    assert.strictEqual(client.isAuthorized(), true);

    await client.heartbeatNow();

    // Invariant: Network failures must NOT revoke offline grace
    assert.strictEqual(client.isAuthorized(), true);
    assert.strictEqual(client.status(), 'OK');

    client.shutdown();
  });

  test('deactivates seat, wipes local lease, and transitions status to NOT_ACTIVATED', async () => {
    const now = Math.floor(Date.now() / 1000);

    mockServer.setLicenseSignRule('/v1/licenses/activate', 'ws_test_key_2026', workspacePrivKeyDerHex, {
      iss: 'seatling',
      sub: 'SEAT-DEACT-TEST',
      aud: 'ws_net',
      product_id: 'prod_net',
      seat_id: 'seat_deact_01',
      hwid: HWIDCollector.getHWID(),
      app_version: '1.0.0',
      iat: now,
      nbf: now,
      exp: now + 14 * 86400,
      offline_grace_days: 14,
      status: 'active',
      entitlements: {},
    });

    const client = new SeatlingClient({
      workspaceId: 'ws_net',
      productId: 'prod_net',
      publicKeys: { ws_test_key_2026: workspacePublicKeyBase64 },
      appVersion: '1.0.0',
      apiBaseUrl: serverBaseUrl,
      storageDir: tmpDir,
    });

    await client.activate('SEAT-DEACT-TEST');
    assert.strictEqual(client.isAuthorized(), true);
    assert.ok(fs.existsSync(path.join(tmpDir, 'lease.seatling')));

    mockServer.setStaticRule('/v1/licenses/deactivate', 200, {
      success: true,
      message: 'Seat successfully deactivated',
    });

    const deactivated = await client.deactivate();
    assert.strictEqual(deactivated, true);
    assert.strictEqual(client.isAuthorized(), false);
    assert.strictEqual(client.status(), 'NOT_ACTIVATED');
    assert.strictEqual(fs.existsSync(path.join(tmpDir, 'lease.seatling')), false);

    const captured = await mockServer.getCaptured();
    const deactReq = captured.find((r: CapturedRequest) => r.url === '/v1/licenses/deactivate');
    assert.ok(deactReq, 'Must have captured request to /v1/licenses/deactivate');
    assert.ok(deactReq.body && typeof deactReq.body.token === 'string');
    assert.strictEqual(deactReq.body.token.split('.').length, 3);

    client.shutdown();
  });

  test('deactivate with force false preserves local state on server failure', async () => {
    const now = Math.floor(Date.now() / 1000);

    mockServer.setLicenseSignRule('/v1/licenses/activate', 'ws_test_key_2026', workspacePrivKeyDerHex, {
      iss: 'seatling',
      sub: 'SEAT-DEACT-ERR',
      aud: 'ws_net',
      product_id: 'prod_net',
      seat_id: 'seat_deact_err',
      hwid: HWIDCollector.getHWID(),
      app_version: '1.0.0',
      iat: now,
      nbf: now,
      exp: now + 14 * 86400,
      offline_grace_days: 14,
      status: 'active',
      entitlements: {},
    });

    mockServer.setStaticRule('/v1/licenses/deactivate', 500, {
      error: 'internal server error',
    });

    const client = new SeatlingClient({
      workspaceId: 'ws_net',
      productId: 'prod_net',
      publicKeys: { ws_test_key_2026: workspacePublicKeyBase64 },
      appVersion: '1.0.0',
      apiBaseUrl: serverBaseUrl,
      storageDir: tmpDir,
    });

    await client.activate('SEAT-DEACT-ERR');
    assert.strictEqual(client.isAuthorized(), true);

    // force: false with server error
    const noForceResult = await client.deactivate(1000, false);
    assert.strictEqual(noForceResult, false);
    assert.strictEqual(client.isAuthorized(), true);
    assert.ok(fs.existsSync(path.join(tmpDir, 'lease.seatling')));

    // force: true with server error completes local teardown
    const forceResult = await client.deactivate(1000, true);
    assert.strictEqual(forceResult, true);
    assert.strictEqual(client.isAuthorized(), false);
    assert.strictEqual(fs.existsSync(path.join(tmpDir, 'lease.seatling')), false);

    client.shutdown();
  });
});
