import * as path from 'node:path';
import * as fs from 'node:fs';

export interface NativeHWIDComponents {
  cpu: string;
  mobo: string;
  disk: string;
  osUuid: string;
}

export interface NativeSeatlingConfig {
  workspaceId: string;
  productId: string;
  publicKeys: Record<string, string>;
  appVersion?: string;
  apiBaseUrl?: string;
  heartbeatIntervalSeconds?: number;
  storageDir?: string;
}

export interface NativeLeaseStatus {
  status: string;
  isAuthorized: boolean;
  seatId?: string;
  maskedKey?: string;
  buyerEmail?: string;
  lastVerifiedAtUnix?: number;
  offlineExpiresAtUnix?: number;
  isWithinOfflineGrace?: boolean;
  portalUrl?: string;
  message?: string;
  entitlementsJson: string;
}

export interface NativeActivationResult {
  success: boolean;
  status: string;
  message: string;
  seatId?: string;
  portalUrl?: string;
  buyerEmail?: string;
  seatsActive?: number;
  seatLimit?: number;
  leaseStatus?: NativeLeaseStatus;
  token?: string;
}

export interface NativeSeatlingClient {
  initialize(): NativeLeaseStatus;
  isAuthorized(): boolean;
  isValid(): boolean;
  status(): string;
  isValidBlocking(timeoutMs?: number): boolean;
  statusBlocking(timeoutMs?: number): NativeLeaseStatus;
  getSessionId(): string;
  getStatus(): NativeLeaseStatus;
  getEntitlementBool(key: string, defaultValue: boolean): boolean;
  getEntitlementNumber(key: string, defaultValue: number): number;
  getEntitlementString(key: string, defaultValue?: string): string;
  activate(licenseKey: string): NativeActivationResult;
  heartbeatNow(): NativeLeaseStatus;
  heartbeatWithTimeout(timeoutMs?: number): NativeLeaseStatus;
  deactivate(timeoutMs?: number, force?: boolean): boolean;
  shutdown(): void;
}

export interface NativeStorageManager {
  getStorageDir(): string;
  getLeasePath(): string;
  getKeystorePath(): string;
  readLease(): string | null;
  writeLease(content: string): boolean;
  readKeystore(): string | null;
  writeKeystore(content: string): boolean;
  deleteLease(): void;
}

export interface NativeHardwareSealedKeystore {
  getPublicKeyBase64(): string;
  getAttestationTier(): string;
  signActivationPopJwt(key: string, hwid: string, hwidComponents: NativeHWIDComponents, appVersion: string, aud: string, timestamp: number, nonce: string, supportedKids?: string[]): string;
  signHeartbeatChallengeJwt(key: string, seatId: string, hwid: string, sessionId: string, appVersion: string, aud: string, timestamp: number, nonce: string, supportedKids?: string[]): string;
  signActivationProof(key: string, hwid: string, timestamp: number, supportedKids?: string[]): string;
  signHeartbeat(key: string, hwid: string, sessionId: string, nonce: string, timestamp: number, supportedKids?: string[]): string;
  signDeactivation(key: string, seatId: string, hwid: string, nonce: string, timestamp: number): string;
}

export interface NativeTokenVerifier {
  verifyLicenseToken(token: string, expectedWorkspaceId: string, expectedProductId: string): string;
  verifyLicenseTokenBound(
    token: string,
    expectedWorkspaceId: string,
    expectedProductId: string,
    expectedHwid: string,
    expectedDevicePubkeyBase64: string
  ): string;
}

export interface NativeStateAndEntitlementCache {
  isAuthorized(): boolean;
  getStatus(): NativeLeaseStatus;
  getEntitlementBool(key: string, defaultValue: boolean): boolean;
  getEntitlementNumber(key: string, defaultValue: number): number;
  getEntitlementString(key: string, defaultValue?: string): string;
  clear(): void;
}

export interface NativeBindings {
  SeatlingClientNative: new (config: NativeSeatlingConfig) => NativeSeatlingClient;
  StorageManagerNative: new (workspaceId: string, productId: string, storageDir?: string) => NativeStorageManager;
  HardwareSealedKeystoreNative: new (workspaceId?: string, productId?: string, storageDir?: string) => NativeHardwareSealedKeystore;
  TokenVerifierNative: new (publicKeys: Record<string, string>) => NativeTokenVerifier;
  StateAndEntitlementCacheNative: new () => NativeStateAndEntitlementCache;
  getHwid(): string;
  getHwidComponents(): NativeHWIDComponents;
  fuzzyMatchQuorum(base: NativeHWIDComponents, current: NativeHWIDComponents): boolean;
  weightedScore(base: NativeHWIDComponents, current: NativeHWIDComponents): number;
}

function loadNative(): NativeBindings {
  const candidatePaths = [
    path.join(__dirname, '..', '..', 'seatling.node'),
    path.join(__dirname, '..', 'seatling.node'),
    path.join(__dirname, 'seatling.node'),
    path.join(__dirname, '..', '..', 'native', 'seatling.node'),
    path.join(__dirname, '..', 'native', 'seatling.node'),
  ];

  for (const p of candidatePaths) {
    if (fs.existsSync(p)) {
      try {
        return require(p) as NativeBindings;
      } catch (err: any) {
        // If require fails on an existing file, let it throw or continue
        console.error(`Failed loading ${p}:`, err.message);
      }
    }
  }

  // Fallback for platform package or direct require
  try {
    return require('@seatling/node-' + process.platform + '-' + process.arch) as NativeBindings;
  } catch {
    throw new Error(
      `Could not load native Seatling Rust core binary for ${process.platform}-${process.arch}. ` +
      `Ensure seatling.node is placed in the native directory or cargo build has been run.`
    );
  }
}

export const native = loadNative();
