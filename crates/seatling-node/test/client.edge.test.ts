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
import { StateAndEntitlementCache } from '../src/cache';
import { LicenseJwtClaims } from '../src/types';

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function base64url(input: Buffer | string): string {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf8');
  return buf.toString('base64url');
}

describe('SeatlingClient Edge Cases & Storage Resilience', () => {
  let tmpDir: string;
  let workspacePublicKeyBase64: string;
  let workspacePrivateKey: crypto.KeyObject;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'seatling-node-edge-test-'));

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

  function getDevicePublicKey(workspaceId = 'ws_edge', productId = 'prod_edge'): string {
    const storage = new StorageManager(workspaceId, productId, tmpDir);
    const ks = new HardwareSealedKeystore(storage);
    return ks.getPublicKeyBase64();
  }

  function signLicenseToken(claims: Partial<LicenseJwtClaims>): string {
    const header = {
      alg: 'EdDSA',
      typ: 'seatling-license+jwt',
      kid: 'ws_edge_key',
    };
    const now = Math.floor(Date.now() / 1000);
    const fullClaims: LicenseJwtClaims = {
      iss: 'seatling',
      sub: 'SEAT-EDGE-TEST',
      aud: 'ws_edge',
      product_id: 'prod_edge',
      seat_id: 'seat_edge_01',
      hwid: HWIDCollector.getHWID(),
      device_key: getDevicePublicKey('ws_edge', 'prod_edge'),
      app_version: '1.0.0',
      iat: now,
      nbf: now,
      exp: now + 14 * 86400,
      offline_grace_days: 14,
      status: 'active',
      entitlements: { feature: true },
      ...claims,
    };

    const headerB64 = base64url(JSON.stringify(header));
    const claimsB64 = base64url(JSON.stringify(fullClaims));
    const signingInput = `${headerB64}.${claimsB64}`;
    const sig = crypto.sign(null, Buffer.from(signingInput, 'utf8'), workspacePrivateKey);
    return `${signingInput}.${base64url(sig)}`;
  }

  test('gracefully handles empty 0-byte lease file without crashing', () => {
    fs.writeFileSync(path.join(tmpDir, 'lease.seatling'), '', 'utf8');

    const client = new SeatlingClient({
      workspaceId: 'ws_edge',
      productId: 'prod_edge',
      publicKeys: { ws_edge_key: workspacePublicKeyBase64 },
      appVersion: '1.0.0',
      storageDir: tmpDir,
    });

    const status = client.initialize();
    assert.strictEqual(status.status, 'TAMPER_OR_SIGNATURE_INVALID');
    assert.strictEqual(client.isAuthorized(), false);
    client.shutdown();
  });

  test('gracefully handles non-JWT garbage bytes in lease file', () => {
    fs.writeFileSync(path.join(tmpDir, 'lease.seatling'), 'not_a_valid_jwt_at_all', 'utf8');

    const client = new SeatlingClient({
      workspaceId: 'ws_edge',
      productId: 'prod_edge',
      publicKeys: { ws_edge_key: workspacePublicKeyBase64 },
      appVersion: '1.0.0',
      storageDir: tmpDir,
    });

    const status = client.initialize();
    assert.strictEqual(status.status, 'TAMPER_OR_SIGNATURE_INVALID');
    assert.strictEqual(client.isAuthorized(), false);
    client.shutdown();
  });

  test('recovers and generates fresh keypair when keystore.bin is corrupted JSON', () => {
    // Write corrupted JSON to keystore.bin
    fs.writeFileSync(path.join(tmpDir, 'keystore.bin'), '{ "version": 2, "broken_json": ', 'utf8');

    const client = new SeatlingClient({
      workspaceId: 'ws_edge',
      productId: 'prod_edge',
      publicKeys: { ws_edge_key: workspacePublicKeyBase64 },
      appVersion: '1.0.0',
      storageDir: tmpDir,
    });

    // Client must self-heal and initialize in unactivated state
    const status = client.initialize();
    assert.strictEqual(status.status, 'NOT_ACTIVATED');
    assert.strictEqual(client.isAuthorized(), false);

    // Keystore should have regenerated
    assert.ok(fs.existsSync(path.join(tmpDir, 'keystore.bin')));
    const content = JSON.parse(fs.readFileSync(path.join(tmpDir, 'keystore.bin'), 'utf8'));
    assert.strictEqual(content.version, 2);

    client.shutdown();
  });

  test('rejects inverted validity window where exp < iat', () => {
    const now = Math.floor(Date.now() / 1000);
    const token = signLicenseToken({
      iat: now,
      exp: now - 3600, // Expired before creation
    });
    fs.writeFileSync(path.join(tmpDir, 'lease.seatling'), token, 'utf8');

    const client = new SeatlingClient({
      workspaceId: 'ws_edge',
      productId: 'prod_edge',
      publicKeys: { ws_edge_key: workspacePublicKeyBase64 },
      appVersion: '1.0.0',
      storageDir: tmpDir,
    });

    const status = client.initialize();
    assert.strictEqual(status.status, 'TAMPER_OR_SIGNATURE_INVALID');
    assert.strictEqual(client.isAuthorized(), false);
    client.shutdown();
  });

  test('accepts iat within 300s clock skew but rejects iat > 300s in the future', () => {
    const now = Math.floor(Date.now() / 1000);

    // 1. iat within 300s skew (e.g. +120s) -> Accepted
    const validSkewToken = signLicenseToken({
      iat: now + 120,
      nbf: now + 120,
      exp: now + 86400,
    });
    fs.writeFileSync(path.join(tmpDir, 'lease.seatling'), validSkewToken, 'utf8');

    const clientValid = new SeatlingClient({
      workspaceId: 'ws_edge',
      productId: 'prod_edge',
      publicKeys: { ws_edge_key: workspacePublicKeyBase64 },
      appVersion: '1.0.0',
      storageDir: tmpDir,
    });
    assert.strictEqual(clientValid.initialize().status, 'OK');
    assert.strictEqual(clientValid.isAuthorized(), true);
    clientValid.shutdown();

    // 2. iat exceeding 300s skew (e.g. +350s) -> Rejected
    const invalidSkewToken = signLicenseToken({
      iat: now + 350,
      nbf: now + 350,
      exp: now + 86400,
    });
    fs.writeFileSync(path.join(tmpDir, 'lease.seatling'), invalidSkewToken, 'utf8');

    const clientInvalid = new SeatlingClient({
      workspaceId: 'ws_edge',
      productId: 'prod_edge',
      publicKeys: { ws_edge_key: workspacePublicKeyBase64 },
      appVersion: '1.0.0',
      storageDir: tmpDir,
    });
    assert.strictEqual(clientInvalid.initialize().status, 'TAMPER_OR_SIGNATURE_INVALID');
    assert.strictEqual(clientInvalid.isAuthorized(), false);
    clientInvalid.shutdown();
  });

  test('rejects token missing mandatory device_key claim', () => {
    const tokenWithoutDeviceKey = signLicenseToken({
      device_key: undefined,
    });
    fs.writeFileSync(path.join(tmpDir, 'lease.seatling'), tokenWithoutDeviceKey, 'utf8');

    const client = new SeatlingClient({
      workspaceId: 'ws_edge',
      productId: 'prod_edge',
      publicKeys: { ws_edge_key: workspacePublicKeyBase64 },
      appVersion: '1.0.0',
      storageDir: tmpDir,
    });

    const status = client.initialize();
    assert.strictEqual(status.status, 'TAMPER_OR_SIGNATURE_INVALID');
    assert.strictEqual(client.isAuthorized(), false);
    client.shutdown();
  });

  test('rejects invalid SemVer format in appVersion config', () => {
    assert.throws(() => {
      new SeatlingClient({
        workspaceId: 'ws_edge',
        productId: 'prod_edge',
        publicKeys: { ws_edge_key: workspacePublicKeyBase64 },
        appVersion: 'invalid-non-semver',
        storageDir: tmpDir,
      });
    }, /not valid SemVer/);
  });

  test('calling shutdown multiple times is safe and idempotent', () => {
    const client = new SeatlingClient({
      workspaceId: 'ws_edge',
      productId: 'prod_edge',
      publicKeys: { ws_edge_key: workspacePublicKeyBase64 },
      appVersion: '1.0.0',
      storageDir: tmpDir,
    });

    client.initialize();
    // Multiple shutdowns must not throw or deadlock
    client.shutdown();
    client.shutdown();
    client.shutdown();
  });

  test('HWIDCollector.getComponents returns copy that resists in-place mutation', () => {
    const c1 = HWIDCollector.getComponents();
    const origCpu = c1.cpu;
    c1.cpu = 'mutated_cpu';
    const c2 = HWIDCollector.getComponents();
    assert.strictEqual(c2.cpu, origCpu);
    assert.notStrictEqual(c2.cpu, 'mutated_cpu');
  });

  test('StateAndEntitlementCache safely ignores prototype chain properties', () => {
    const cache = new StateAndEntitlementCache();
    // Inherited prototype properties should return the provided default value
    const val = cache.getEntitlement('toString', 'default_val');
    assert.strictEqual(val, 'default_val');
    const valObj = cache.getEntitlement('valueOf', 'default_val');
    assert.strictEqual(valObj, 'default_val');
  });

  test('HardwareSealedKeystore queries attestation tier dynamically', () => {
    const storage = new StorageManager('ws_edge', 'prod_edge', tmpDir);
    const ks = new HardwareSealedKeystore(storage);
    const tier = ks.getAttestationTier();
    assert.ok(tier === 'hardware_sealed' || tier === 'software');
  });

  test('SeatlingClient handles negative, NaN, and overlong timeout clamping safely', () => {
    const client = new SeatlingClient({
      workspaceId: 'ws_edge',
      productId: 'prod_edge',
      publicKeys: { ws_edge_key: workspacePublicKeyBase64 },
      appVersion: '1.0.0',
      storageDir: tmpDir,
    });
    // Should not throw or crash on non-standard timeout values
    assert.strictEqual(client.isValidBlocking(-500), false);
    assert.strictEqual(client.isValidBlocking(NaN), false);
    assert.strictEqual(client.isValidBlocking(0xffffffffffff), false);
    client.shutdown();
  });
});
