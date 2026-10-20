export type AttestationTier = 'hardware_sealed' | 'software';

export type LicenseStatusCode =
  | 'OK'
  | 'OFFLINE_GRACE_VALID'
  | 'NOT_ACTIVATED'
  | 'OFFLINE_GRACE_EXPIRED'
  | 'SEATS_EXHAUSTED'
  | 'REQUIRES_PORTAL_DEACTIVATION'
  | 'LICENSE_SUSPENDED_OR_REVOKED'
  | 'VERSION_CEILING_EXCEEDED'
  | 'TAMPER_OR_SIGNATURE_INVALID'
  | 'NETWORK_ERROR'
  | 'TIME_TAMPER_DETECTED'
  | 'INVALID_PRODUCT_OR_WORKSPACE'
  | 'KEY_REVOKED_UPDATE_REQUIRED'
  | 'INVALID_CONFIGURATION';

export type SeatlingStatus = LicenseStatusCode;

export type EntitlementValue = boolean | number | string;

export interface HWIDComponents {
  cpu: string;
  mobo: string;
  disk: string;
  os_uuid: string;
}

export interface SeatlingConfig {
  workspaceId: string;
  productId: string;
  publicKeys: Record<string, string>; // Map of kid -> Base64 or Base64URL encoded 32-byte Ed25519 public key (HARDWARE_ANCHOR_V7.md §7.1.1)
  appVersion: string;
  apiBaseUrl?: string; // Default: 'https://api.seatling.com'
  heartbeatIntervalSeconds?: number; // Default: 14400 (4 hours)
  storageDir?: string; // Optional custom override for test environments
}

export type Config = SeatlingConfig;

export interface LeaseStatus {
  status: LicenseStatusCode;
  isAuthorized: boolean;
  seatId?: string;
  maskedKey?: string;
  buyerEmail?: string;
  lastVerifiedAt?: string;
  offlineExpiresAt?: string;
  isWithinOfflineGrace?: boolean;
  portalUrl?: string;
  message?: string;
  entitlements: Record<string, EntitlementValue>;
}

export interface ActivationResult {
  success: boolean;
  status: LicenseStatusCode;
  message: string;
  seatId?: string;
  portalUrl?: string;
  buyerEmail?: string;
  seatsActive?: number;
  seatLimit?: number;
  leaseStatus?: LeaseStatus;
  token?: string;
}

export interface ActivationPopClaims {
  iss: string;
  sub: string;
  aud: string;
  hwid: string;
  hwid_components: HWIDComponents;
  app_version: string;
  attestation_tier: AttestationTier;
  iat: number;
  jti: string;
  supported_kids: string[];
}

export interface LicenseJwtClaims {
  iss: string;
  sub: string;
  aud: string;
  product_id: string;
  seat_id: string;
  masked_key?: string;
  buyer_email?: string;
  hwid: string;
  device_key?: string;
  app_version: string;
  iat: number;
  nbf?: number;
  exp: number;
  offline_grace_days?: number;
  status: string;
  entitlements: Record<string, EntitlementValue>;
}

export interface HeartbeatChallengeClaims {
  iss: string;
  sub: string;
  aud: string;
  seat_id: string;
  hwid: string;
  session_id: string;
  app_version: string;
  iat: number;
  jti: string;
  supported_kids: string[];
}

export interface HeartbeatAckClaims {
  iss: string;
  sub: string;
  aud: string;
  product_id: string;
  seat_id: string;
  status: string;
  iat: number;
  exp: number;
  jti: string;
  entitlements: Record<string, EntitlementValue>;
}

export interface StoredKeystoreFile {
  version: number;
  tier: AttestationTier;
  public_key: string;
  iv: string;
  auth_tag: string;
  ciphertext: string;
  dpapi_blob?: string;
}
