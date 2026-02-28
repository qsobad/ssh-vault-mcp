/**
 * SSH Command Executor
 * Executes commands on remote hosts via SSH, with SFTP file transfer
 */

import { Client, type ConnectConfig, type SFTPWrapper } from 'ssh2';

// SSH connection info (replaces old Host type dependency)
export interface SSHHostInfo {
  hostname: string;
  port: number;
  username: string;
  credential: string;
  authType: 'key' | 'password';
}

export interface ExecutionResult {
  output: string;
  stderr: string;
  exitCode: number;
}

export interface FileTransferResult {
  success: boolean;
  bytesTransferred: number;
  error?: string;
}

export interface FileListEntry {
  name: string;
  size: number;
  modifyTime: number;
  isDirectory: boolean;
  permissions: number;
}

export class SSHExecutor {
  /**
   * Execute a command on a remote host
   */
  async execute(
    host: SSHHostInfo,
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
  async testConnection(host: SSHHostInfo): Promise<{
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
    host: SSHHostInfo,
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
    host: SSHHostInfo,
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

  /**
   * Create an SFTP connection helper
   */
  private connectSftp(host: SSHHostInfo, timeoutMs: number = 30000): Promise<{ client: Client; sftp: SFTPWrapper }> {
    return new Promise((resolve, reject) => {
      const client = new Client();
      const timeoutId = setTimeout(() => {
        client.end();
        reject(new Error(`SFTP connection timed out after ${timeoutMs}ms`));
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
        client.sftp((err, sftp) => {
          clearTimeout(timeoutId);
          if (err) { client.end(); reject(err); return; }
          resolve({ client, sftp });
        });
      });

      client.on('error', (err) => {
        clearTimeout(timeoutId);
        reject(err);
      });

      client.connect(connectConfig);
    });
  }

  /**
   * Upload content to a remote file
   */
  async upload(
    host: SSHHostInfo,
    remotePath: string,
    content: Buffer,
    timeoutMs: number = 60000
  ): Promise<FileTransferResult> {
    let conn: { client: Client; sftp: SFTPWrapper } | null = null;
    try {
      conn = await this.connectSftp(host, timeoutMs);
      const { client, sftp } = conn;

      return new Promise((resolve) => {
        const writeStream = sftp.createWriteStream(remotePath);
        let bytesTransferred = 0;

        writeStream.on('close', () => {
          client.end();
          resolve({ success: true, bytesTransferred });
        });

        writeStream.on('error', (err: Error) => {
          client.end();
          resolve({ success: false, bytesTransferred: 0, error: err.message });
        });

        bytesTransferred = content.length;
        writeStream.end(content);
      });
    } catch (error) {
      conn?.client.end();
      return { success: false, bytesTransferred: 0, error: error instanceof Error ? error.message : 'Upload failed' };
    }
  }

  /**
   * Download a remote file
   */
  async download(
    host: SSHHostInfo,
    remotePath: string,
    timeoutMs: number = 60000
  ): Promise<{ success: boolean; content?: Buffer; size?: number; error?: string }> {
    let conn: { client: Client; sftp: SFTPWrapper } | null = null;
    try {
      conn = await this.connectSftp(host, timeoutMs);
      const { client, sftp } = conn;

      return new Promise((resolve) => {
        const chunks: Buffer[] = [];
        const readStream = sftp.createReadStream(remotePath);

        readStream.on('data', (chunk: Buffer) => {
          chunks.push(chunk);
        });

        readStream.on('end', () => {
          client.end();
          const content = Buffer.concat(chunks);
          resolve({ success: true, content, size: content.length });
        });

        readStream.on('error', (err: Error) => {
          client.end();
          resolve({ success: false, error: err.message });
        });
      });
    } catch (error) {
      conn?.client.end();
      return { success: false, error: error instanceof Error ? error.message : 'Download failed' };
    }
  }

  /**
   * List files in a remote directory
   */
  async listFiles(
    host: SSHHostInfo,
    remotePath: string,
    timeoutMs: number = 30000
  ): Promise<{ success: boolean; files?: FileListEntry[]; error?: string }> {
    let conn: { client: Client; sftp: SFTPWrapper } | null = null;
    try {
      conn = await this.connectSftp(host, timeoutMs);
      const { client, sftp } = conn;

      return new Promise((resolve) => {
        sftp.readdir(remotePath, (err, list) => {
          client.end();
          if (err) {
            resolve({ success: false, error: err.message });
            return;
          }
          const files: FileListEntry[] = list.map(item => ({
            name: item.filename,
            size: item.attrs.size,
            modifyTime: item.attrs.mtime,
            isDirectory: (item.attrs.mode! & 0o40000) !== 0,
            permissions: item.attrs.mode! & 0o7777,
          }));
          resolve({ success: true, files });
        });
      });
    } catch (error) {
      conn?.client.end();
      return { success: false, error: error instanceof Error ? error.message : 'List failed' };
    }
  }
}
