import { Worker } from 'node:worker_threads';

export interface CapturedRequest {
  url: string;
  method: string;
  body: any;
}

export class ThreadedMockServer {
  private worker: Worker | null = null;
  private port: number = 0;

  public async start(): Promise<string> {
    const workerCode = `
      const http = require('node:http');
      const crypto = require('node:crypto');
      const { parentPort } = require('node:worker_threads');

      let rules = [];
      let captured = [];

      function base64url(buf) {
        return buf.toString('base64url');
      }

      function signToken(header, claims, privKeyDerHex) {
        const hB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
        const cB64 = Buffer.from(JSON.stringify(claims)).toString('base64url');
        const signingInput = \`\${hB64}.\${cB64}\`;
        const keyObj = crypto.createPrivateKey({
          key: Buffer.from(privKeyDerHex, 'hex'),
          format: 'der',
          type: 'pkcs8',
        });
        const sig = crypto.sign(null, Buffer.from(signingInput, 'utf8'), keyObj);
        return \`\${signingInput}.\${base64url(sig)}\`;
      }

      const server = http.createServer((req, res) => {
        let data = '';
        req.on('data', chunk => { data += chunk; });
        req.on('end', () => {
          let jsonBody = {};
          try {
            if (data) jsonBody = JSON.parse(data);
          } catch {}

          const record = { url: req.url, method: req.method, body: jsonBody };
          captured.push(record);

          const ruleIndex = rules.findIndex(r => r.path === req.url && (!r.method || r.method === req.method));
          if (ruleIndex !== -1) {
            const rule = rules[ruleIndex];
            if (rule.once) {
              rules.splice(ruleIndex, 1);
            }

            let responseBody = rule.body;

            if (rule.signLicenseForDevice && record.body && record.body.token) {
              try {
                const parts = record.body.token.split('.');
                const popClaims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
                const header = { alg: 'EdDSA', typ: 'seatling-license+jwt', kid: rule.kid };
                const claims = {
                  ...rule.licenseClaims,
                  device_key: popClaims.iss,
                  sub: popClaims.sub || rule.licenseClaims.sub,
                };
                const token = signToken(header, claims, rule.privKeyDerHex);
                responseBody = { token };
              } catch (e) {
                console.error('[MockServer] signLicenseForDevice error', e);
              }
            } else if (rule.signHeartbeatAck && record.body && record.body.token) {
              try {
                const parts = record.body.token.split('.');
                const challengeClaims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
                const nonce = rule.overrideNonce || challengeClaims.jti;
                const header = { alg: 'EdDSA', typ: 'seatling-heartbeat-ack+jwt', kid: rule.kid };
                const claims = {
                  ...rule.ackClaims,
                  jti: nonce,
                  sub: challengeClaims.sub || rule.ackClaims.sub,
                  seat_id: challengeClaims.seat_id || rule.ackClaims.seat_id,
                };
                const token = signToken(header, claims, rule.privKeyDerHex);
                responseBody = { token, ...(rule.extraResponseFields || {}) };
              } catch (e) {
                console.error('[MockServer] signHeartbeatAck error', e);
              }
            }

            res.writeHead(rule.status, {
              'Content-Type': 'application/json',
              'Connection': 'close',
            });
            res.end(JSON.stringify(responseBody));
          } else {
            res.writeHead(500, {
              'Content-Type': 'application/json',
              'Connection': 'close',
            });
            res.end(JSON.stringify({ error: 'no matching rule for ' + req.url }));
          }
        });
      });

      server.listen(0, '127.0.0.1', () => {
        parentPort.postMessage({ type: 'listening', port: server.address().port });
      });

      parentPort.on('message', msg => {
        if (msg.type === 'set_rule') {
          rules.push(msg.rule);
        } else if (msg.type === 'clear') {
          rules = [];
          captured = [];
        } else if (msg.type === 'get_captured') {
          parentPort.postMessage({ type: 'captured_list', captured });
        } else if (msg.type === 'close') {
          if (typeof server.closeAllConnections === 'function') {
            server.closeAllConnections();
          }
          server.close(() => {
            parentPort.postMessage({ type: 'closed' });
          });
        }
      });
    `;

    this.worker = new Worker(workerCode, { eval: true });

    return new Promise((resolve, reject) => {
      this.worker!.on('message', (msg: any) => {
        if (msg.type === 'listening') {
          this.port = msg.port;
          resolve(`http://127.0.0.1:${this.port}`);
        }
      });
      this.worker!.on('error', reject);
    });
  }

  public setStaticRule(path: string, status: number, body: any, method = 'POST', once = false): void {
    this.worker!.postMessage({
      type: 'set_rule',
      rule: { path, status, body, method, once },
    });
  }

  public setLicenseSignRule(
    path: string,
    kid: string,
    privKeyDerHex: string,
    licenseClaims: any,
    status = 200,
    once = false
  ): void {
    this.worker!.postMessage({
      type: 'set_rule',
      rule: {
        path,
        status,
        method: 'POST',
        once,
        signLicenseForDevice: true,
        kid,
        privKeyDerHex,
        licenseClaims,
      },
    });
  }

  public setHeartbeatAckRule(
    path: string,
    kid: string,
    privKeyDerHex: string,
    ackClaims: any,
    options?: { overrideNonce?: string; extraResponseFields?: any; status?: number; once?: boolean }
  ): void {
    this.worker!.postMessage({
      type: 'set_rule',
      rule: {
        path,
        status: options?.status || 200,
        method: 'POST',
        once: options?.once ?? false,
        signHeartbeatAck: true,
        kid,
        privKeyDerHex,
        ackClaims,
        overrideNonce: options?.overrideNonce,
        extraResponseFields: options?.extraResponseFields,
      },
    });
  }

  public clear(): void {
    this.worker!.postMessage({ type: 'clear' });
  }

  public async getCaptured(): Promise<CapturedRequest[]> {
    return new Promise(resolve => {
      const handler = (msg: any) => {
        if (msg.type === 'captured_list') {
          this.worker!.off('message', handler);
          resolve(msg.captured);
        }
      };
      this.worker!.on('message', handler);
      this.worker!.postMessage({ type: 'get_captured' });
    });
  }

  public async stop(): Promise<void> {
    if (!this.worker) return;
    return new Promise(resolve => {
      const handler = (msg: any) => {
        if (msg.type === 'closed') {
          this.worker!.off('message', handler);
          this.worker!.terminate().then(() => {
            this.worker = null;
            resolve();
          });
        }
      };
      this.worker!.on('message', handler);
      this.worker!.postMessage({ type: 'close' });
    });
  }
}
