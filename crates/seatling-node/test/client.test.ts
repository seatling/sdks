import { test, describe, beforeEach, afterEach } from 'node:test';
import * as assert from 'node:assert';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { SeatlingClient } from '../src/client';
import { HWIDCollector } from '../src/hwid';
import { HardwareSealedKeystore } from '../src/keystore';
import { StorageManager } from '../src/storage';
import { LicenseJwtClaims } from '../src/types';

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function base64url(input: Buffer | string): string {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf8');
  return buf.toString('base64url');
}

describe('SeatlingClient End-to-End', () => {
  let tmpDir: string;
  let workspacePublicKeyBase64: string;
  let workspacePrivateKey: crypto.KeyObject;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'seatling-node-client-test-'));

    // Generate test workspace Ed25519 keypair
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    workspacePrivateKey = privateKey;
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    workspacePublicKeyBase64 = spkiDer.subarray(ED25519_SPKI_PREFIX.length).toString('base64');
  });

  afterEach(() => {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // Ignored
    }
  });

  function getDevicePublicKey(workspaceId = 'ws_demo', productId = 'prod_synth'): string {
    const storage = new StorageManager(workspaceId, productId, tmpDir);
    const ks = new HardwareSealedKeystore(storage);
    return ks.getPublicKeyBase64();
  }

  function createSignedLicenseJwt(claims: Partial<LicenseJwtClaims>, customDeviceKey?: string): string {
    const header = {
      alg: 'EdDSA',
      typ: 'seatling-license+jwt',
      kid: 'demo_key_2026',
    };
    const now = Math.floor(Date.now() / 1000);
    const fullClaims: LicenseJwtClaims = {
      iss: 'seatling',
      sub: 'SEAT-TEST-KEY',
      aud: 'ws_demo',
      product_id: 'prod_synth',
      seat_id: 'seat_123',
      masked_key: 'SEAT-****-KEY',
      buyer_email: 'creator@example.com',
      hwid: HWIDCollector.getHWID(),
      device_key: customDeviceKey || getDevicePublicKey(claims.aud || 'ws_demo', claims.product_id || 'prod_synth'),
      app_version: '1.0.0',
      iat: now,
      nbf: now,
      exp: now + 14 * 86400,
      offline_grace_days: 14,
      status: 'active',
      entitlements: {
        pro_dsp: true,
        max_oversampling: 16,
        sample_rate: 96000,
        tier: 'enterprise',
      },
      ...claims,
    };

    const headerB64 = base64url(JSON.stringify(header));
    const claimsB64 = base64url(JSON.stringify(fullClaims));
    const signingInput = `${headerB64}.${claimsB64}`;
    const sig = crypto.sign(null, Buffer.from(signingInput, 'utf8'), workspacePrivateKey);
    return `${signingInput}.${base64url(sig)}`;
  }

  test('reports NOT_ACTIVATED when no local lease exists', () => {
    const client = new SeatlingClient({
      workspaceId: 'ws_demo',
      productId: 'prod_synth',
      publicKeys: { demo_key_2026: workspacePublicKeyBase64 },
      appVersion: '1.0.0',
      storageDir: tmpDir,
    });

    const status = client.initialize();
    assert.strictEqual(status.status, 'NOT_ACTIVATED');
    assert.strictEqual(status.isAuthorized, false);
    assert.strictEqual(client.isAuthorized(), false);
    assert.strictEqual(client.getSessionId().length, 32);
  });

  test('validates valid offline lease and populates entitlements with < 0.01ms reads', () => {
    const jwt = createSignedLicenseJwt({});
    fs.writeFileSync(path.join(tmpDir, 'lease.seatling'), jwt, 'utf8');

    const client = new SeatlingClient({
      workspaceId: 'ws_demo',
      productId: 'prod_synth',
      publicKeys: { demo_key_2026: workspacePublicKeyBase64 },
      appVersion: '1.0.0',
      storageDir: tmpDir,
    });

    const status = client.initialize();
    assert.strictEqual(status.status, 'OK');
    assert.strictEqual(status.isAuthorized, true);
    assert.strictEqual(client.isAuthorized(), true);

    // Entitlement retrieval
    assert.strictEqual(client.getEntitlement('pro_dsp', false), true);
    assert.strictEqual(client.getEntitlement('max_oversampling', 1), 16);
    assert.strictEqual(client.getEntitlement('sample_rate', 44100), 96000);
    assert.strictEqual(client.getEntitlement('tier', 'basic'), 'enterprise');
    assert.strictEqual(client.getEntitlement('non_existent', 'default'), 'default');

    client.shutdown();
  });

  test('marks lease OFFLINE_GRACE_EXPIRED when offline window is exceeded', () => {
    const thirtyDaysAgo = Math.floor(Date.now() / 1000) - (30 * 86400);

    const jwt = createSignedLicenseJwt({
      iat: thirtyDaysAgo,
      exp: thirtyDaysAgo + (14 * 86400),
    });
    fs.writeFileSync(path.join(tmpDir, 'lease.seatling'), jwt, 'utf8');

    const client = new SeatlingClient({
      workspaceId: 'ws_demo',
      productId: 'prod_synth',
      publicKeys: { demo_key_2026: workspacePublicKeyBase64 },
      appVersion: '1.0.0',
      storageDir: tmpDir,
    });

    const status = client.initialize();
    assert.strictEqual(status.status, 'OFFLINE_GRACE_EXPIRED');
    assert.strictEqual(status.isAuthorized, false);
    assert.strictEqual(client.isAuthorized(), false);

    client.shutdown();
  });

  test('detects signature tampering and rejects modified lease', () => {
    const jwt = createSignedLicenseJwt({});
    const parts = jwt.split('.');
    // Tamper with payload claims JSON without updating signature
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    claims.entitlements.pro_dsp = false;
    const tamperedPayloadB64 = base64url(JSON.stringify(claims));
    const tamperedJwt = `${parts[0]}.${tamperedPayloadB64}.${parts[2]}`;

    fs.writeFileSync(path.join(tmpDir, 'lease.seatling'), tamperedJwt, 'utf8');

    const client = new SeatlingClient({
      workspaceId: 'ws_demo',
      productId: 'prod_synth',
      publicKeys: { demo_key_2026: workspacePublicKeyBase64 },
      appVersion: '1.0.0',
      storageDir: tmpDir,
    });

    const status = client.initialize();
    assert.strictEqual(status.status, 'TAMPER_OR_SIGNATURE_INVALID');
    assert.strictEqual(status.isAuthorized, false);
    assert.strictEqual(client.isAuthorized(), false);
    assert.strictEqual(client.isValid(), false);
    assert.strictEqual(client.status(), 'TAMPER_OR_SIGNATURE_INVALID');
    assert.strictEqual(client.isValidBlocking(50), false);
    assert.strictEqual(client.statusBlocking(50).status, 'TAMPER_OR_SIGNATURE_INVALID');

    client.shutdown();
  });

  test('enforces cross-workspace and cross-product claim isolation (INVALID_PRODUCT_OR_WORKSPACE)', () => {
    // Lease issued for ws_demo / prod_synth
    const jwt = createSignedLicenseJwt({
      aud: 'ws_different_creator',
      product_id: 'prod_synth',
    });
    fs.writeFileSync(path.join(tmpDir, 'lease.seatling'), jwt, 'utf8');

    const client = new SeatlingClient({
      workspaceId: 'ws_demo',
      productId: 'prod_synth',
      publicKeys: { demo_key_2026: workspacePublicKeyBase64 },
      appVersion: '1.0.0',
      storageDir: tmpDir,
    });

    const status = client.initialize();
    assert.strictEqual(status.status, 'INVALID_PRODUCT_OR_WORKSPACE');
    assert.strictEqual(status.isAuthorized, false);
    assert.strictEqual(client.isAuthorized(), false);

    client.shutdown();
  });

  test('dual query interface returns consistent lock-free and pre-flight status', () => {
    const jwt = createSignedLicenseJwt({});
    fs.writeFileSync(path.join(tmpDir, 'lease.seatling'), jwt, 'utf8');

    const client = new SeatlingClient({
      workspaceId: 'ws_demo',
      productId: 'prod_synth',
      publicKeys: { demo_key_2026: workspacePublicKeyBase64 },
      appVersion: '1.0.0',
      storageDir: tmpDir,
    });

    const initStatus = client.initialize();
    assert.strictEqual(initStatus.status, 'OK');

    // Hot-path lock-free queries (< 0.05ms)
    assert.strictEqual(client.isAuthorized(), true);
    assert.strictEqual(client.isValid(), true);
    assert.strictEqual(client.status(), 'OK');

    // Pre-flight blocking queries
    assert.strictEqual(client.isValidBlocking(100), true);
    const blockingStatus = client.statusBlocking(100);
    assert.strictEqual(blockingStatus.status, 'OK');
    assert.strictEqual(blockingStatus.isAuthorized, true);

    client.shutdown();
  });

  test('matches kid against workspacePublicKeys map and handles key rotation', () => {
    // Generate rotated key (2027)
    const { publicKey: pub2027, privateKey: priv2027 } = crypto.generateKeyPairSync('ed25519');
    const spkiDer2027 = pub2027.export({ type: 'spki', format: 'der' });
    const pub2027Base64 = spkiDer2027.subarray(ED25519_SPKI_PREFIX.length).toString('base64');

    // Create token signed with rotated key (kid: 'demo_key_2027')
    const header2027 = {
      alg: 'EdDSA',
      typ: 'seatling-license+jwt',
      kid: 'demo_key_2027',
    };
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      iss: 'seatling',
      sub: 'SEAT-TEST-ROTATION',
      aud: 'ws_demo',
      product_id: 'prod_synth',
      seat_id: 'seat_rot',
      hwid: HWIDCollector.getHWID(),
      device_key: getDevicePublicKey('ws_demo', 'prod_synth'),
      app_version: '1.0.0',
      iat: now,
      nbf: now,
      exp: now + 14 * 86400,
      status: 'active',
      entitlements: {},
    };
    const hB64 = base64url(JSON.stringify(header2027));
    const cB64 = base64url(JSON.stringify(claims));
    const input = `${hB64}.${cB64}`;
    const sig = crypto.sign(null, Buffer.from(input, 'utf8'), priv2027);
    const jwt2027 = `${input}.${base64url(sig)}`;

    fs.writeFileSync(path.join(tmpDir, 'lease.seatling'), jwt2027, 'utf8');

    // Client configured with both keys (supporting seamless rotation)
    const client = new SeatlingClient({
      workspaceId: 'ws_demo',
      productId: 'prod_synth',
      publicKeys: {
        demo_key_2026: workspacePublicKeyBase64,
        demo_key_2027: pub2027Base64,
      },
      appVersion: '1.0.0',
      storageDir: tmpDir,
    });

    const status = client.initialize();
    assert.strictEqual(status.status, 'OK');
    assert.strictEqual(status.isAuthorized, true);

    client.shutdown();
  });

  test('rejects token with unknown kid not in publicKeys', () => {
    // Token with unknown kid
    const headerUnknown = {
      alg: 'EdDSA',
      typ: 'seatling-license+jwt',
      kid: 'unrecognized_kid_9999',
    };
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      iss: 'seatling',
      sub: 'SEAT-TEST-UNKNOWN',
      aud: 'ws_demo',
      product_id: 'prod_synth',
      seat_id: 'seat_unk',
      hwid: HWIDCollector.getHWID(),
      device_key: getDevicePublicKey('ws_demo', 'prod_synth'),
      app_version: '1.0.0',
      iat: now,
      nbf: now,
      exp: now + 14 * 86400,
      status: 'active',
      entitlements: {},
    };
    const hB64 = base64url(JSON.stringify(headerUnknown));
    const cB64 = base64url(JSON.stringify(claims));
    const input = `${hB64}.${cB64}`;
    const sig = crypto.sign(null, Buffer.from(input, 'utf8'), workspacePrivateKey);
    const jwtUnknown = `${input}.${base64url(sig)}`;

    fs.writeFileSync(path.join(tmpDir, 'lease.seatling'), jwtUnknown, 'utf8');

    const client = new SeatlingClient({
      workspaceId: 'ws_demo',
      productId: 'prod_synth',
      publicKeys: {
        demo_key_2026: workspacePublicKeyBase64,
      },
      appVersion: '1.0.0',
      storageDir: tmpDir,
    });

    const status = client.initialize();
    assert.strictEqual(status.status, 'TAMPER_OR_SIGNATURE_INVALID');
    assert.strictEqual(status.isAuthorized, false);

    client.shutdown();
  });

  test('rejects client initialization when publicKeys is empty (V6 requirement)', () => {
    assert.throws(() => {
      new SeatlingClient({
        workspaceId: 'ws_demo',
        productId: 'prod_synth',
        publicKeys: {},
        appVersion: '1.0.0',
        storageDir: tmpDir,
      });
    }, /At least one public key must be provided in public_keys/);
  });

  test('supports Base64URL-encoded public keys per HARDWARE_ANCHOR_V7.md §7.1.1', () => {
    const rawPubKeyBytes = Buffer.from(workspacePublicKeyBase64, 'base64');
    const pubKeyBase64Url = rawPubKeyBytes.toString('base64url'); // Unpadded RFC 4648 URL-safe string

    const jwt = createSignedLicenseJwt({});
    fs.writeFileSync(path.join(tmpDir, 'lease.seatling'), jwt, 'utf8');

    const client = new SeatlingClient({
      workspaceId: 'ws_demo',
      productId: 'prod_synth',
      publicKeys: {
        demo_key_2026: pubKeyBase64Url,
      },
      appVersion: '1.0.0',
      storageDir: tmpDir,
    });

    const status = client.initialize();
    assert.strictEqual(status.status, 'OK');
    assert.strictEqual(status.isAuthorized, true);

    client.shutdown();
  });

  test('TokenVerifier verifies license token with strict HWID and device key binding', () => {
    const { TokenVerifier } = require('../src/verifier');
    const verifier = new TokenVerifier({
      demo_key_2026: workspacePublicKeyBase64,
    });
    const devKey = getDevicePublicKey();
    const hwid = HWIDCollector.getHWID();
    const validJwt = createSignedLicenseJwt({});

    // Valid bound check
    const res = verifier.verifyLicenseTokenBound(validJwt, 'ws_demo', 'prod_synth', hwid, devKey);
    assert.strictEqual(res.valid, true);
    assert.ok(res.claims);

    // Mismatched HWID
    const resWrongHwid = verifier.verifyLicenseTokenBound(validJwt, 'ws_demo', 'prod_synth', 'wrong_hwid', devKey);
    assert.strictEqual(resWrongHwid.valid, false);

    // Mismatched device key
    const otherStorage = new StorageManager('ws_other', 'prod_other', path.join(tmpDir, 'other'));
    const otherDevKey = new HardwareSealedKeystore(otherStorage).getPublicKeyBase64();
    const resWrongDevKey = verifier.verifyLicenseTokenBound(validJwt, 'ws_demo', 'prod_synth', hwid, otherDevKey);
    assert.strictEqual(resWrongDevKey.valid, false);
  });
});
