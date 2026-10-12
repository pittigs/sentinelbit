/**
 * SentinelBit Zero-Knowledge TypeScript SDK
 * Zero NPM dependencies - Uses native Web Crypto API
 */

export interface VaultItem {
  id: string;
  type: 'login' | 'secure_note' | 'credit_card' | 'identity' | 'passkey' | 'ssh_key';
  title: string;
  folder?: string;
  favorite?: boolean;
  data: Record<string, any>;
  createdAt: string;
  updatedAt: string;
}

export interface SecureSendResult {
  id: string;
  shareUrl: string;
  burnLimit: number;
  expiresAt: string;
}

export class SentinelBitClient {
  private baseURL: string;
  private token: string | null = null;
  private masterKey: CryptoKey | null = null;

  constructor(baseURL: string = window.location.origin) {
    this.baseURL = baseURL.replace(/\/$/, '');
  }

  /**
   * Derives a cryptographic key using PBKDF2
   */
  private async deriveKey(password: string, salt: string, iterations: number = 100000): Promise<CryptoKey> {
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: enc.encode(salt),
        iterations,
        hash: 'SHA-256'
      },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Zero-Knowledge Login
   */
  async login(username: string, masterPassword: string, totpCode?: string): Promise<boolean> {
    const initRes = await fetch(`${this.baseURL}/api/auth/login-init`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });

    if (!initRes.ok) throw new Error(`Login init failed: ${initRes.statusText}`);
    const initData = await initRes.json();

    const [clientSalt, serverSalt] = initData.auth_salt.split(':');
    const enc = new TextEncoder();

    // Derive client auth key
    const baseAuthKey = await crypto.subtle.importKey(
      'raw',
      enc.encode(masterPassword),
      'PBKDF2',
      false,
      ['deriveBits']
    );

    const clientAuthBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: enc.encode(clientSalt),
        iterations: 100000,
        hash: 'SHA-256'
      },
      baseAuthKey,
      256
    );

    const clientAuthHex = Array.from(new Uint8Array(clientAuthBits))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    const verifyRes = await fetch(`${this.baseURL}/api/auth/login-verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        client_auth_key: clientAuthHex,
        totp_code: totpCode
      })
    });

    if (!verifyRes.ok) throw new Error('Invalid credentials');
    const loginData = await verifyRes.json();

    this.token = loginData.token;
    this.masterKey = await this.deriveKey(masterPassword, loginData.enc_salt);
    return true;
  }

  /**
   * Fetch and decrypt all vault items
   */
  async listItems(): Promise<VaultItem[]> {
    if (!this.token || !this.masterKey) throw new Error('Not authenticated');

    const res = await fetch(`${this.baseURL}/api/vault/items`, {
      headers: { Authorization: `Bearer ${this.token}` }
    });

    if (!res.ok) throw new Error(`Failed to list items: ${res.statusText}`);
    const items = await res.json();

    const decrypted: VaultItem[] = [];
    for (const item of items) {
      try {
        const payload = JSON.parse(item.encrypted_payload);
        const iv = new Uint8Array(payload.iv.match(/.{1,2}/g)!.map((byte: string) => parseInt(byte, 16)));
        const dataBytes = new Uint8Array(payload.data.match(/.{1,2}/g)!.map((byte: string) => parseInt(byte, 16)));

        const decryptedBuf = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv },
          this.masterKey,
          dataBytes
        );

        const dataObj = JSON.parse(new TextDecoder().decode(decryptedBuf));
        decrypted.push({
          id: item.id,
          type: item.type,
          title: item.title,
          folder: item.folder,
          favorite: item.favorite,
          data: dataObj,
          createdAt: item.created_at,
          updatedAt: item.updated_at
        });
      } catch (err) {
        console.warn(`Failed to decrypt item ${item.id}`, err);
      }
    }

    return decrypted;
  }
}
