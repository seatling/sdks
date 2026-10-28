import { native } from './native';
import { HWIDComponents } from './types';

export class HWIDCollector {
  private static cachedComponents: HWIDComponents | null = null;
  private static cachedHWID: string | null = null;

  /**
   * Reads normalized hardware components via the Rust core engine.
   * Runs non-elevated without triggering OS dialogs.
   */
  public static getComponents(): HWIDComponents {
    if (this.cachedComponents) {
      return { ...this.cachedComponents };
    }
    const c = native.getHwidComponents();
    this.cachedComponents = {
      cpu: c.cpu,
      mobo: c.mobo,
      disk: c.disk,
      os_uuid: c.osUuid,
    };
    return { ...this.cachedComponents };
  }

  /**
   * Computes composite HWID digest via the Rust core engine.
   */
  public static getHWID(): string {
    if (this.cachedHWID) {
      return this.cachedHWID;
    }
    this.cachedHWID = native.getHwid();
    return this.cachedHWID;
  }

  /**
   * Evaluates weighted quorum fuzzy matching via the Rust core engine (score >= 70).
   */
  public static fuzzyMatchQuorum(base: HWIDComponents, current: HWIDComponents): boolean {
    return native.fuzzyMatchQuorum(
      { cpu: base.cpu, mobo: base.mobo, disk: base.disk, osUuid: base.os_uuid },
      { cpu: current.cpu, mobo: current.mobo, disk: current.disk, osUuid: current.os_uuid }
    );
  }

  /**
   * Computes the weighted HWID match score between base and current components.
   * mobo: 35, cpu: 25, disk: 20, os_uuid: 20 (Passing score >= 70).
   */
  public static weightedScore(base: HWIDComponents, current: HWIDComponents): number {
    return native.weightedScore(
      { cpu: base.cpu, mobo: base.mobo, disk: base.disk, osUuid: base.os_uuid },
      { cpu: current.cpu, mobo: current.mobo, disk: current.disk, osUuid: current.os_uuid }
    );
  }

  public static _clearCache(): void {
    this.cachedComponents = null;
    this.cachedHWID = null;
  }
}
