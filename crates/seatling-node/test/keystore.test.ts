import { test, describe, beforeEach, afterEach } from 'node:test';
import * as assert from 'node:assert';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { StorageManager } from '../src/storage';
import { HardwareSealedKeystore } from '../src/keystore';
import { HWIDCollector } from '../src/hwid';

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

describe('HardwareSealedKeystore', () => {
  let tmpDir: string;
  let storage: StorageManager;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'seatling-node-keystore-test-'));
    storage = new StorageManager('ws_test', 'prod_test', tmpDir);
  });

  afterEach(() => {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // Ignored
    }
  });

  test('generates and persists hardware-sealed Ed25519 keypair in keystore.bin', () => {
    assert.strictEqual(storage.getWorkspaceId(), 'ws_test');
    assert.strictEqual(storage.getProductId(), 'prod_test');
    const keystore = new HardwareSealedKeystore(storage);
    const pubKeyBase64 = keystore.getPublicKeyBase64();

    assert.ok(pubKeyBase64, 'Public key must be generated');
    const pubKeyBytes = Buffer.from(pubKeyBase64, 'base64');
    assert.strictEqual(pubKeyBytes.length, 32, 'Ed25519 public key must be 32 bytes');

    // Verify keystore.bin exists on disk
    const keystorePath = storage.getKeystorePath();
    assert.ok(fs.existsSync(keystorePath), 'keystore.bin must exist on disk');

    const fileContent = JSON.parse(fs.readFileSync(keystorePath, 'utf8'));
    assert.strictEqual(fileContent.version, 2);
    assert.strictEqual(fileContent.tier, 'hardware_sealed');
    assert.ok(fileContent.iv);
    assert.ok(fileContent.auth_tag);
    assert.ok(fileContent.ciphertext);
    assert.strictEqual(
      Buffer.from(fileContent.ciphertext, 'base64').length,
      104,
      'V4 encrypted keystore payload must be exactly 104 bytes'
    );
  });

  test('successfully loads and unseals existing keystore on subsequent invocations', () => {
    const keystore1 = new HardwareSealedKeystore(storage);
    const pubKey1 = keystore1.getPublicKeyBase64();

    // Instantiate a new keystore pointing to the same storage
    const keystore2 = new HardwareSealedKeystore(storage);
    const pubKey2 = keystore2.getPublicKeyBase64();

    assert.strictEqual(pubKey1, pubKey2, 'Subsequent keystore loads must yield identical public key');
  });

  test('signs activation PoP JWT and verifies signature against public key', () => {
    const keystore = new HardwareSealedKeystore(storage);
    const pubKeyBase64 = keystore.getPublicKeyBase64();
    const key = 'SEAT-1111-2222-3333-4444';
    const hwid = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const components = HWIDCollector.getComponents();
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = 'pop_nonce_123';

    const supportedKids = ['custom_kid_v1'];
    const popJwt = keystore.signActivationPopJwt(key, hwid, components, '1.0.0', 'https://api.seatling.com', timestamp, nonce, supportedKids);
    assert.ok(popJwt, 'PoP JWT must be generated');

    const parts = popJwt.split('.');
    assert.strictEqual(parts.length, 3, 'JWT must have 3 parts');

    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    assert.strictEqual(header.alg, 'EdDSA');
    assert.strictEqual(header.typ, 'seatling-activate-pop+jwt');

    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    assert.strictEqual(claims.sub, key);
    assert.strictEqual(claims.jti, nonce);
    assert.strictEqual(claims.app_version, '1.0.0');
    assert.deepStrictEqual(claims.supported_kids, ['custom_kid_v1']);

    const spkiDer = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(pubKeyBase64, 'base64')]);
    const pubKeyObject = crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });

    const signingInput = `${parts[0]}.${parts[1]}`;
    const isValid = crypto.verify(null, Buffer.from(signingInput, 'utf8'), pubKeyObject, Buffer.from(parts[2], 'base64url'));
    assert.strictEqual(isValid, true, 'Proof-of-Possession EdDSA JWT signature must verify successfully');
  });

  test('signs heartbeat challenge JWT and verifies signature', () => {
    const keystore = new HardwareSealedKeystore(storage);
    const pubKeyBase64 = keystore.getPublicKeyBase64();
    const key = 'SEAT-1111-2222-3333-4444';
    const seatId = 'seat_999';
    const hwid = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const sessionId = '0123456789abcdef0123456789abcdef';
    const nonce = 'random_nonce_12345';
    const timestamp = Math.floor(Date.now() / 1000);

    const supportedKids = ['custom_kid_v1', 'custom_kid_v2'];
    const hbJwt = keystore.signHeartbeatChallengeJwt(key, seatId, hwid, sessionId, '1.0.0', 'https://api.seatling.com', timestamp, nonce, supportedKids);
    const parts = hbJwt.split('.');
    assert.strictEqual(parts.length, 3);

    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    assert.strictEqual(header.typ, 'seatling-heartbeat-challenge+jwt');

    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    assert.strictEqual(claims.seat_id, seatId);
    assert.strictEqual(claims.jti, nonce);
    assert.deepStrictEqual(claims.supported_kids, ['custom_kid_v1', 'custom_kid_v2']);

    const spkiDer = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(pubKeyBase64, 'base64')]);
    const pubKeyObject = crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });

    const signingInput = `${parts[0]}.${parts[1]}`;
    const isValid = crypto.verify(null, Buffer.from(signingInput, 'utf8'), pubKeyObject, Buffer.from(parts[2], 'base64url'));
    assert.strictEqual(isValid, true, 'Heartbeat challenge EdDSA JWT signature must verify successfully');
  });

  test('signs auxiliary proofs (activation proof, legacy heartbeat, deactivation) and verifies signatures', () => {
    const keystore = new HardwareSealedKeystore(storage);
    const pubKeyBase64 = keystore.getPublicKeyBase64();
    const spkiDer = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(pubKeyBase64, 'base64')]);
    const pubKeyObject = crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });

    const key = 'SEAT-PROOF-KEY';
    const hwid = 'hwid_hash_12345';
    const timestamp = Math.floor(Date.now() / 1000);

    // 1. signActivationProof
    const actProof = keystore.signActivationProof(key, hwid, timestamp, ['kid_1']);
    assert.ok(actProof);
    const actParts = actProof.split('.');
    assert.strictEqual(actParts.length, 3);
    const isActValid = crypto.verify(null, Buffer.from(`${actParts[0]}.${actParts[1]}`, 'utf8'), pubKeyObject, Buffer.from(actParts[2], 'base64url'));
    assert.strictEqual(isActValid, true);

    // 2. signHeartbeat
    const hbProof = keystore.signHeartbeat(key, hwid, 'sess_1', 'nonce_1', timestamp, ['kid_1']);
    assert.ok(hbProof);
    const hbParts = hbProof.split('.');
    assert.strictEqual(hbParts.length, 3);
    const isHbValid = crypto.verify(null, Buffer.from(`${hbParts[0]}.${hbParts[1]}`, 'utf8'), pubKeyObject, Buffer.from(hbParts[2], 'base64url'));
    assert.strictEqual(isHbValid, true);

    // 3. signDeactivation (returns standard base64 signature over formatted payload string)
    const deactSigB64 = keystore.signDeactivation(key, 'seat_1', hwid, 'nonce_deact', timestamp);
    assert.ok(deactSigB64);
    const deactPayload = `seatling:deactivate:v1|${key}|seat_1|${hwid}|nonce_deact|${timestamp}`;
    const isDeactValid = crypto.verify(
      null,
      Buffer.from(deactPayload, 'utf8'),
      pubKeyObject,
      Buffer.from(deactSigB64, 'base64')
    );
    assert.strictEqual(isDeactValid, true);
  });
});
