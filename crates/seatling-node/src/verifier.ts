import { native, NativeTokenVerifier } from './native';
import { LicenseJwtClaims } from './types';

export class TokenVerifier {
  private readonly inner: NativeTokenVerifier;

  constructor(publicKeys: Record<string, string>) {
    this.inner = new native.TokenVerifierNative(publicKeys);
  }

  /**
   * Verifies an EdDSA License JWT via the Rust core engine.
   */
  public verifyLicenseToken(
    token: string,
    expectedWorkspaceId: string,
    expectedProductId: string
  ): { valid: boolean; claims?: LicenseJwtClaims; reason?: string } {
    try {
      const claimsJson = this.inner.verifyLicenseToken(token, expectedWorkspaceId, expectedProductId);
      const claims: LicenseJwtClaims = JSON.parse(claimsJson);
      return { valid: true, claims };
    } catch (err: any) {
      return { valid: false, reason: err.message };
    }
  }

  /**
   * Cryptographically verifies an EdDSA License JWT strictly bound to HWID and device public key.
   */
  public verifyLicenseTokenBound(
    token: string,
    expectedWorkspaceId: string,
    expectedProductId: string,
    expectedHwid: string,
    expectedDevicePubkeyBase64: string
  ): { valid: boolean; claims?: LicenseJwtClaims; reason?: string } {
    try {
      const claimsJson = this.inner.verifyLicenseTokenBound(
        token,
        expectedWorkspaceId,
        expectedProductId,
        expectedHwid,
        expectedDevicePubkeyBase64
      );
      const claims: LicenseJwtClaims = JSON.parse(claimsJson);
      return { valid: true, claims };
    } catch (err: any) {
      return { valid: false, reason: err.message };
    }
  }

  /**
   * Checks whether the current time is within the allowed offline grace period.
   */
  public isWithinOfflineGrace(expiresAtUnix: number): { valid: boolean; expiresAtUnix: number } {
    const now = Math.floor(Date.now() / 1000);
    return {
      valid: now <= expiresAtUnix,
      expiresAtUnix,
    };
  }
}
