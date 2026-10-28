import { EntitlementValue, LeaseStatus, LicenseStatusCode, LicenseJwtClaims } from './types';

export interface LeaseSnapshot {
  status: LicenseStatusCode;
  isAuthorized: boolean;
  seatId?: string;
  maskedKey?: string;
  buyerEmail?: string;
  lastVerifiedAtUnix?: number;
  offlineExpiresAtUnix?: number;
  isWithinOfflineGrace?: boolean;
  portalUrl?: string;
  message?: string;
  entitlements: Record<string, EntitlementValue>;
}

export class StateAndEntitlementCache {
  private currentSnapshot: LeaseSnapshot;

  constructor() {
    this.currentSnapshot = {
      status: 'NOT_ACTIVATED',
      isAuthorized: false,
      entitlements: {},
    };
  }

  public isAuthorized(): boolean {
    return this.currentSnapshot.isAuthorized;
  }

  public getEntitlement<T extends EntitlementValue>(key: string, defaultValue: T): T {
    if (
      this.currentSnapshot.entitlements &&
      Object.prototype.hasOwnProperty.call(this.currentSnapshot.entitlements, key)
    ) {
      const val = this.currentSnapshot.entitlements[key];
      if (typeof val === typeof defaultValue) {
        return val as T;
      }
    }
    return defaultValue;
  }

  public getStatus(): LeaseStatus {
    const s = this.currentSnapshot;
    return {
      status: s.status,
      isAuthorized: s.isAuthorized,
      seatId: s.seatId,
      maskedKey: s.maskedKey,
      buyerEmail: s.buyerEmail,
      lastVerifiedAt: s.lastVerifiedAtUnix ? new Date(s.lastVerifiedAtUnix * 1000).toISOString() : undefined,
      offlineExpiresAt: s.offlineExpiresAtUnix ? new Date(s.offlineExpiresAtUnix * 1000).toISOString() : undefined,
      isWithinOfflineGrace: s.isWithinOfflineGrace,
      portalUrl: s.portalUrl,
      message: s.message,
      entitlements: { ...s.entitlements },
    };
  }

  public updateFromPayload(
    status: LicenseStatusCode,
    isAuthorized: boolean,
    payload?: LicenseJwtClaims,
    offlineExpiresAtUnix?: number,
    isWithinOfflineGrace?: boolean,
    portalUrl?: string,
    message?: string
  ): void {
    this.currentSnapshot = {
      status,
      isAuthorized,
      seatId: payload?.seat_id,
      maskedKey: payload?.masked_key,
      buyerEmail: payload?.buyer_email,
      lastVerifiedAtUnix: payload?.iat,
      offlineExpiresAtUnix,
      isWithinOfflineGrace,
      portalUrl,
      message,
      entitlements: payload?.entitlements ? { ...payload.entitlements } : {},
    };
  }

  public updateStatusOnly(status: LicenseStatusCode, isAuthorized: boolean, message?: string, portalUrl?: string): void {
    this.currentSnapshot = {
      ...this.currentSnapshot,
      status,
      isAuthorized,
      message: message ?? this.currentSnapshot.message,
      portalUrl: portalUrl ?? this.currentSnapshot.portalUrl,
    };
  }

  public clear(): void {
    this.currentSnapshot = {
      status: 'NOT_ACTIVATED',
      isAuthorized: false,
      entitlements: {},
    };
  }
}
