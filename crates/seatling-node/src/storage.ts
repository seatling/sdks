import { native, NativeStorageManager } from './native';

export class StorageManager {
  private readonly inner: NativeStorageManager;
  private readonly workspaceId: string;
  private readonly productId: string;

  constructor(workspaceId: string, productId: string, customDir?: string) {
    this.workspaceId = workspaceId;
    this.productId = productId;
    this.inner = new native.StorageManagerNative(workspaceId, productId, customDir);
  }

  public getWorkspaceId(): string {
    return this.workspaceId;
  }

  public getProductId(): string {
    return this.productId;
  }

  public getDirectory(): string {
    return this.inner.getStorageDir();
  }

  public getKeystorePath(): string {
    return this.inner.getKeystorePath();
  }

  public getLeasePath(): string {
    return this.inner.getLeasePath();
  }

  public readKeystore(): string | null {
    return this.inner.readKeystore();
  }

  public writeKeystore(content: string): void {
    this.inner.writeKeystore(content);
  }

  public readLease(): string | null {
    return this.inner.readLease();
  }

  public writeLease(content: string): void {
    this.inner.writeLease(content);
  }

  public deleteLease(): void {
    this.inner.deleteLease();
  }
}
