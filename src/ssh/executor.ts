/**
 * SSH Command Executor
 * Executes commands on remote hosts via SSH
 */

import { Client, type ConnectConfig } from 'ssh2';
import type { Host } from '../types.js';

export interface ExecutionResult {
  output: string;
  stderr: string;
  exitCode: number;
}

export class SSHExecutor {
  /**
   * Execute a command on a remote host
   */
  async execute(
    host: Host,
    command: string,
    timeoutMs: number = 30000
  ): Promise<ExecutionResult> {
    return new Promise((resolve, reject) => {
      const client = new Client();
      let stdout = '';
      let stderr = '';
      let exitCode = 0;
      let timeoutId: NodeJS.Timeout;

      const cleanup = () => {
        clearTimeout(timeoutId);
        client.end();
      };

      timeoutId = setTimeout(() => {
        cleanup();
        reject(new Error(`Command timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      const connectConfig: ConnectConfig = {
        host: host.hostname,
        port: host.port,
        username: host.username,
        readyTimeout: 10000,
      };

      // Set authentication method
      if (host.authType === 'key') {
        connectConfig.privateKey = host.credential;
      } else {
        connectConfig.password = host.credential;
      }

      client.on('ready', () => {
        client.exec(command, (err, stream) => {
          if (err) {
            cleanup();
            reject(err);
            return;
          }

          stream.on('close', (code: number) => {
            exitCode = code;
            cleanup();
            resolve({ output: stdout, stderr, exitCode });
          });

          stream.on('data', (data: Buffer) => {
            stdout += data.toString();
          });

          stream.stderr.on('data', (data: Buffer) => {
            stderr += data.toString();
          });
        });
      });

      client.on('error', (err) => {
        cleanup();
        reject(err);
      });

      client.connect(connectConfig);
    });
  }

  /**
   * Test connection to a host
   */
  async testConnection(host: Host): Promise<{
    success: boolean;
    latencyMs: number;
    error?: string;
  }> {
    const start = Date.now();
    
    try {
      const result = await this.execute(host, 'echo "connected"', 10000);
      return {
        success: result.exitCode === 0,
        latencyMs: Date.now() - start,
      };
    } catch (error) {
      return {
        success: false,
        latencyMs: Date.now() - start,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Execute multiple commands in sequence
   */
  async executeMultiple(
    host: Host,
    commands: string[],
    timeoutMs: number = 30000
  ): Promise<ExecutionResult[]> {
    const results: ExecutionResult[] = [];
    
    for (const command of commands) {
      const result = await this.execute(host, command, timeoutMs);
      results.push(result);
      
      // Stop on non-zero exit code
      if (result.exitCode !== 0) {
        break;
      }
    }

    return results;
  }

  /**
   * Execute a command with streaming output callback
   */
  async executeWithStream(
    host: Host,
    command: string,
    onStdout: (data: string) => void,
    onStderr: (data: string) => void,
    timeoutMs: number = 30000
  ): Promise<number> {
    return new Promise((resolve, reject) => {
      const client = new Client();
      let exitCode = 0;
      let timeoutId: NodeJS.Timeout;

      const cleanup = () => {
        clearTimeout(timeoutId);
        client.end();
      };

      timeoutId = setTimeout(() => {
        cleanup();
        reject(new Error(`Command timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      const connectConfig: ConnectConfig = {
        host: host.hostname,
        port: host.port,
        username: host.username,
        readyTimeout: 10000,
      };

      if (host.authType === 'key') {
        connectConfig.privateKey = host.credential;
      } else {
        connectConfig.password = host.credential;
      }

      client.on('ready', () => {
        client.exec(command, (err, stream) => {
          if (err) {
            cleanup();
            reject(err);
            return;
          }

          stream.on('close', (code: number) => {
            exitCode = code;
            cleanup();
            resolve(exitCode);
          });

          stream.on('data', (data: Buffer) => {
            onStdout(data.toString());
          });

          stream.stderr.on('data', (data: Buffer) => {
            onStderr(data.toString());
          });
        });
      });

      client.on('error', (err) => {
        cleanup();
        reject(err);
      });

      client.connect(connectConfig);
    });
  }
}
