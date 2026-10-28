import { native, NativeLeaseStatus, NativeSeatlingClient } from './native';
import {
  ActivationResult,
  EntitlementValue,
  LeaseStatus,
  LicenseStatusCode,
  SeatlingConfig,
} from './types';

function sanitizeEntitlements(raw: any): Record<string, EntitlementValue> {
  const result: Record<string, EntitlementValue> = {};
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    for (const key of Object.keys(raw)) {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        continue;
      }
      const val = raw[key];
      if (typeof val === 'boolean' || typeof val === 'number' || typeof val === 'string') {
        result[key] = val;
      }
    }
  }
  return result;
}

function clampTimeoutMs(timeoutMs?: number, defaultMs: number = 8000): number {
  if (timeoutMs === undefined || Number.isNaN(timeoutMs)) {
    return defaultMs;
  }
  if (timeoutMs < 0) {
    return 1;
  }
  if (timeoutMs > 0xffffffff) {
    return 0xffffffff;
  }
  return Math.floor(timeoutMs);
}

function convertNativeLeaseStatus(nativeStatus: NativeLeaseStatus): LeaseStatus {
  let entitlements: Record<string, EntitlementValue> = {};
  if (nativeStatus.entitlementsJson) {
    try {
      const parsed = JSON.parse(nativeStatus.entitlementsJson);
      entitlements = sanitizeEntitlements(parsed);
    } catch {
      entitlements = {};
    }
  }

  return {
    status: nativeStatus.status as LicenseStatusCode,
    isAuthorized: nativeStatus.isAuthorized,
    seatId: nativeStatus.seatId,
    maskedKey: nativeStatus.maskedKey,
    buyerEmail: nativeStatus.buyerEmail,
    lastVerifiedAt: nativeStatus.lastVerifiedAtUnix
      ? new Date(nativeStatus.lastVerifiedAtUnix * 1000).toISOString()
      : undefined,
    offlineExpiresAt: nativeStatus.offlineExpiresAtUnix
      ? new Date(nativeStatus.offlineExpiresAtUnix * 1000).toISOString()
      : undefined,
    isWithinOfflineGrace: nativeStatus.isWithinOfflineGrace,
    portalUrl: nativeStatus.portalUrl,
    message: nativeStatus.message,
    entitlements,
  };
}

export class SeatlingClient {
  private readonly nativeClient: NativeSeatlingClient;

  constructor(config: SeatlingConfig) {
    this.nativeClient = new native.SeatlingClientNative({
      workspaceId: config.workspaceId,
      productId: config.productId,
      publicKeys: config.publicKeys,
      appVersion: config.appVersion,
      apiBaseUrl: config.apiBaseUrl,
      heartbeatIntervalSeconds: config.heartbeatIntervalSeconds,
      storageDir: config.storageDir,
    });
  }

  /**
   * Factory method conforming to HARDWARE_ANCHOR_V6.md §7.1.1 (Seatling::init).
   * Creates client instance and immediately runs synchronous startup check.
   */
  public static init(config: SeatlingConfig): SeatlingClient {
    const client = new SeatlingClient(config);
    client.initialize();
    return client;
  }

  /**
   * Initializes the client synchronously on startup (< 1ms).
   * Validates local hardware-sealed cache and begins background heartbeat if valid.
   * Never blocks on network I/O.
   */
  public initialize(): LeaseStatus {
    const raw = this.nativeClient.initialize();
    return convertNativeLeaseStatus(raw);
  }

  /**
   * Synchronous, sub-microsecond authorization check (< 0.01ms / ~50ns).
   * Safe to call on high-frequency UI rendering or request handlers.
   */
  public isAuthorized(): boolean {
    return this.nativeClient.isAuthorized();
  }

  /**
   * Lock-free runtime query per HARDWARE_ANCHOR_V3 §7.4.1 (< 0.05ms atomic read).
   * Safe to call on real-time rendering, high-frequency paint loops, or request handlers.
   */
  public isValid(): boolean {
    return this.nativeClient.isValid();
  }

  /**
   * Lock-free runtime status query per HARDWARE_ANCHOR_V3 §7.4.1.
   */
  public status(): LicenseStatusCode {
    return this.nativeClient.status() as LicenseStatusCode;
  }

  /**
   * Synchronous pre-flight query per HARDWARE_ANCHOR_V3 §7.4.1 (< 2ms cached, up to timeoutMs if sync needed).
   * Verifies hardware-sealed keystore, clock tampering, and performs heartbeat if needed.
   */
  public isValidBlocking(timeoutMs: number = 8000): boolean {
    return this.nativeClient.isValidBlocking(clampTimeoutMs(timeoutMs));
  }

  /**
   * Synchronous pre-flight status query per HARDWARE_ANCHOR_V3 §7.4.1.
   */
  public statusBlocking(timeoutMs: number = 8000): LeaseStatus {
    return convertNativeLeaseStatus(this.nativeClient.statusBlocking(clampTimeoutMs(timeoutMs)));
  }

  /**
   * Retrieves the 128-bit random hex process session ID.
   */
  public getSessionId(): string {
    return this.nativeClient.getSessionId();
  }

  /**
   * Retrieves an entitlement value with type-safe fallback.
   */
  public getEntitlement<T extends EntitlementValue>(key: string, defaultValue: T): T {
    if (typeof defaultValue === 'boolean') {
      return this.nativeClient.getEntitlementBool(key, defaultValue) as T;
    } else if (typeof defaultValue === 'number') {
      return this.nativeClient.getEntitlementNumber(key, defaultValue) as T;
    } else if (typeof defaultValue === 'string') {
      return this.nativeClient.getEntitlementString(key, defaultValue) as T;
    }
    return defaultValue;
  }

  public getEntitlementBool(key: string, defaultValue: boolean = false): boolean {
    return this.nativeClient.getEntitlementBool(key, defaultValue);
  }

  public getEntitlementNumber(key: string, defaultValue: number = 0): number {
    return this.nativeClient.getEntitlementNumber(key, defaultValue);
  }

  public getEntitlementString(key: string, defaultValue: string = ''): string {
    return this.nativeClient.getEntitlementString(key, defaultValue);
  }

  /**
   * Returns current lease snapshot and status.
   */
  public getStatus(): LeaseStatus {
    return convertNativeLeaseStatus(this.nativeClient.getStatus());
  }

  /**
   * Activates a license key with Proof-of-Possession signed by the hardware-sealed keystore.
   */
  public async activate(licenseKey: string): Promise<ActivationResult> {
    const res = this.nativeClient.activate(licenseKey.trim());
    return {
      success: res.success,
      status: res.status as LicenseStatusCode,
      message: res.message,
      seatId: res.seatId,
      portalUrl: res.portalUrl,
      buyerEmail: res.buyerEmail,
      seatsActive: res.seatsActive,
      seatLimit: res.seatLimit,
      leaseStatus: res.leaseStatus ? convertNativeLeaseStatus(res.leaseStatus) : undefined,
      token: res.token,
    };
  }

  /**
   * Triggers an immediate 1-RTT mutual-challenge heartbeat in the background.
   */
  public async heartbeatNow(): Promise<LeaseStatus> {
    return convertNativeLeaseStatus(this.nativeClient.heartbeatNow());
  }

  /**
   * Triggers a heartbeat with explicit timeout in milliseconds.
   */
  public async heartbeatWithTimeout(timeoutMs: number = 8000): Promise<LeaseStatus> {
    return convertNativeLeaseStatus(this.nativeClient.heartbeatWithTimeout(clampTimeoutMs(timeoutMs)));
  }

  /**
   * Explicitly releases seat allocation on the Seatling server via EdDSA JWT deactivation proof.
   * If the network is unreachable, defaults to completing local lease teardown (force = true).
   */
  public async deactivate(timeoutMs: number = 8000, force: boolean = true): Promise<boolean> {
    return this.nativeClient.deactivate(clampTimeoutMs(timeoutMs), force);
  }

  /**
   * Stops background heartbeat scheduler and flushes state.
   */
  public shutdown(): void {
    this.nativeClient.shutdown();
  }
}

export const Seatling = SeatlingClient;
