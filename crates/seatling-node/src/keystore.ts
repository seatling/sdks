import { native, NativeHardwareSealedKeystore } from './native';
import { AttestationTier, HWIDComponents } from './types';
import { StorageManager } from './storage';

export class HardwareSealedKeystore {
  private readonly inner: NativeHardwareSealedKeystore;

  constructor(storage: StorageManager) {
    this.inner = new native.HardwareSealedKeystoreNative(
      storage.getWorkspaceId(),
      storage.getProductId(),
      storage.getDirectory()
    );
  }

  public getPublicKeyBase64(): string {
    return this.inner.getPublicKeyBase64();
  }

  public getAttestationTier(): AttestationTier {
    return this.inner.getAttestationTier() as AttestationTier;
  }

  public signActivationPopJwt(
    key: string,
    hwid: string,
    hwidComponents: HWIDComponents,
    appVersion: string,
    aud: string,
    timestamp: number,
    nonce: string,
    supportedKids?: string[]
  ): string {
    return this.inner.signActivationPopJwt(
      key,
      hwid,
      {
        cpu: hwidComponents.cpu,
        mobo: hwidComponents.mobo,
        disk: hwidComponents.disk,
        osUuid: hwidComponents.os_uuid,
      },
      appVersion,
      aud,
      timestamp,
      nonce,
      supportedKids
    );
  }

  public signHeartbeatChallengeJwt(
    key: string,
    seatId: string,
    hwid: string,
    sessionId: string,
    appVersion: string,
    aud: string,
    timestamp: number,
    nonce: string,
    supportedKids?: string[]
  ): string {
    return this.inner.signHeartbeatChallengeJwt(
      key,
      seatId,
      hwid,
      sessionId,
      appVersion,
      aud,
      timestamp,
      nonce,
      supportedKids
    );
  }

  public signActivationProof(
    key: string,
    hwid: string,
    timestamp: number,
    supportedKids?: string[]
  ): string {
    return this.inner.signActivationProof(key, hwid, timestamp, supportedKids);
  }

  public signHeartbeat(
    key: string,
    hwid: string,
    sessionId: string,
    nonce: string,
    timestamp: number,
    supportedKids?: string[]
  ): string {
    return this.inner.signHeartbeat(key, hwid, sessionId, nonce, timestamp, supportedKids);
  }

  public signDeactivation(key: string, seatId: string, hwid: string, nonce: string, timestamp: number): string {
    return this.inner.signDeactivation(key, seatId, hwid, nonce, timestamp);
  }
}
