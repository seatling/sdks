import { test, describe } from 'node:test';
import * as assert from 'node:assert';
import { HWIDCollector } from '../src/hwid';
import { HWIDComponents } from '../src/types';

describe('HWIDCollector', () => {
  test('generates valid 64-character SHA-256 component hashes', () => {
    HWIDCollector._clearCache();
    const components = HWIDCollector.getComponents();

    assert.ok(components.cpu, 'CPU component must be present');
    assert.ok(components.mobo, 'Motherboard component must be present');
    assert.ok(components.disk, 'Disk component must be present');
    assert.ok(components.os_uuid, 'OS UUID component must be present');

    const sha256Regex = /^[a-f0-9]{64}$/;
    assert.match(components.cpu, sha256Regex);
    assert.match(components.mobo, sha256Regex);
    assert.match(components.disk, sha256Regex);
    assert.match(components.os_uuid, sha256Regex);
  });

  test('computes composite HWID as 64-character SHA-256', () => {
    const hwid = HWIDCollector.getHWID();
    assert.match(hwid, /^[a-f0-9]{64}$/);
  });

  test('enforces weighted fuzzy matching quorum (passing score >= 70)', () => {
    const base: HWIDComponents = {
      cpu: '1111111111111111111111111111111111111111111111111111111111111111',
      mobo: '2222222222222222222222222222222222222222222222222222222222222222',
      disk: '3333333333333333333333333333333333333333333333333333333333333333',
      os_uuid: '4444444444444444444444444444444444444444444444444444444444444444',
    };

    // 4 of 4 match: 100 points -> pass
    assert.strictEqual(HWIDCollector.weightedScore(base, { ...base }), 100);
    assert.strictEqual(HWIDCollector.fuzzyMatchQuorum(base, { ...base }), true);

    // Disk swapped (20 points lost -> 80 points) -> pass
    const diskSwapped: HWIDComponents = {
      ...base,
      disk: '9999999999999999999999999999999999999999999999999999999999999999',
    };
    assert.strictEqual(HWIDCollector.weightedScore(base, diskSwapped), 80);
    assert.strictEqual(HWIDCollector.fuzzyMatchQuorum(base, diskSwapped), true);

    // CPU swapped (25 points lost -> 75 points) -> pass
    const cpuSwapped: HWIDComponents = {
      ...base,
      cpu: '8888888888888888888888888888888888888888888888888888888888888888',
    };
    assert.strictEqual(HWIDCollector.weightedScore(base, cpuSwapped), 75);
    assert.strictEqual(HWIDCollector.fuzzyMatchQuorum(base, cpuSwapped), true);

    // Motherboard swapped (35 points lost -> 65 points < 70) -> FAILS quorum in V6
    const moboSwapped: HWIDComponents = {
      ...base,
      mobo: '7777777777777777777777777777777777777777777777777777777777777777',
    };
    assert.strictEqual(HWIDCollector.weightedScore(base, moboSwapped), 65);
    assert.strictEqual(HWIDCollector.fuzzyMatchQuorum(base, moboSwapped), false);

    // CPU + Disk replaced (45 points lost -> 55 points) -> fails quorum
    const twoSwapped: HWIDComponents = {
      ...base,
      cpu: '8888888888888888888888888888888888888888888888888888888888888888',
      disk: '9999999999999999999999999999999999999999999999999999999999999999',
    };
    assert.strictEqual(HWIDCollector.weightedScore(base, twoSwapped), 55);
    assert.strictEqual(HWIDCollector.fuzzyMatchQuorum(base, twoSwapped), false);
  });
});
