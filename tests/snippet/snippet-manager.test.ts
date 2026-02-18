import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { SnippetManager } from '../../src/snippet/manager.js';
import { promises as fs } from 'fs';
import path from 'path';
import os from 'os';

describe('SnippetManager', () => {
  let manager: SnippetManager;
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'snippet-test-'));
    manager = new SnippetManager(tmpDir);
    await manager.init();
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  // --- CRUD ---

  describe('save', () => {
    it('should create a new snippet and return metadata', async () => {
      const meta = await manager.save({
        name: 'my-api-key',
        content: 'sk-secret-12345',
        description: 'OpenAI API key for production',
        tags: ['credentials', 'openai'],
        language: 'text',
      });

      expect(meta.name).toBe('my-api-key');
      expect(meta.description).toBe('OpenAI API key for production');
      expect(meta.tags).toEqual(['credentials', 'openai']);
      expect(meta.id).toBeDefined();
      // Meta should NOT contain content
      expect((meta as any).content).toBeUndefined();
    });

    it('should update existing snippet by name', async () => {
      await manager.save({
        name: 'deploy-script',
        content: 'echo v1',
        description: 'Deploy v1',
      });

      const updated = await manager.save({
        name: 'deploy-script',
        content: 'echo v2',
        description: 'Deploy v2',
        tags: ['deploy'],
      });

      expect(updated.description).toBe('Deploy v2');
      expect(updated.tags).toEqual(['deploy']);

      // Verify content was updated
      const full = manager.getContent('deploy-script');
      expect(full?.content).toBe('echo v2');
    });

    it('should default language to text', async () => {
      const meta = await manager.save({
        name: 'note',
        content: 'just a note',
        description: 'A simple note',
      });
      expect(meta.language).toBe('text');
    });
  });

  describe('getMeta', () => {
    it('should return metadata without content', async () => {
      await manager.save({
        name: 'secret',
        content: 'super-secret-value',
        description: 'A secret thing',
      });

      const meta = manager.getMeta('secret');
      expect(meta).toBeDefined();
      expect(meta!.name).toBe('secret');
      expect(meta!.description).toBe('A secret thing');
      expect((meta as any).content).toBeUndefined();
    });

    it('should return undefined for non-existent snippet', () => {
      expect(manager.getMeta('nope')).toBeUndefined();
    });
  });

  describe('getContent', () => {
    it('should return full snippet including content', async () => {
      await manager.save({
        name: 'my-key',
        content: 'sk-12345',
        description: 'API key',
      });

      const full = manager.getContent('my-key');
      expect(full).toBeDefined();
      expect(full!.content).toBe('sk-12345');
      expect(full!.name).toBe('my-key');
    });

    it('should return undefined for non-existent snippet', () => {
      expect(manager.getContent('nope')).toBeUndefined();
    });
  });

  describe('list', () => {
    beforeEach(async () => {
      await manager.save({ name: 'bash-deploy', content: '#!/bin/bash\ndeploy', description: 'Deploy script', tags: ['deploy', 'bash'], language: 'bash' });
      await manager.save({ name: 'py-migrate', content: 'import db; db.migrate()', description: 'DB migration', tags: ['db', 'python'], language: 'python' });
      await manager.save({ name: 'api-key-prod', content: 'sk-xxx', description: 'Production API key', tags: ['credentials'] });
    });

    it('should list all snippets as metadata', () => {
      const list = manager.list();
      expect(list).toHaveLength(3);
      // No content in any item
      list.forEach(s => expect((s as any).content).toBeUndefined());
    });

    it('should filter by tags', () => {
      const list = manager.list({ tags: ['credentials'] });
      expect(list).toHaveLength(1);
      expect(list[0].name).toBe('api-key-prod');
    });

    it('should filter by language', () => {
      const list = manager.list({ language: 'bash' });
      expect(list).toHaveLength(1);
      expect(list[0].name).toBe('bash-deploy');
    });

    it('should search by query in name', () => {
      const list = manager.list({ query: 'deploy' });
      expect(list).toHaveLength(1);
      expect(list[0].name).toBe('bash-deploy');
    });

    it('should search by query in description', () => {
      const list = manager.list({ query: 'migration' });
      expect(list).toHaveLength(1);
      expect(list[0].name).toBe('py-migrate');
    });

    it('should search by query in tags', () => {
      const list = manager.list({ query: 'python' });
      expect(list).toHaveLength(1);
      expect(list[0].name).toBe('py-migrate');
    });

    it('should return empty for no matches', () => {
      expect(manager.list({ tags: ['nonexistent'] })).toHaveLength(0);
    });
  });

  describe('delete', () => {
    it('should delete existing snippet', async () => {
      await manager.save({ name: 'temp', content: 'x', description: 'temp' });
      const deleted = await manager.delete('temp');
      expect(deleted).toBe(true);
      expect(manager.getMeta('temp')).toBeUndefined();
    });

    it('should return false for non-existent', async () => {
      expect(await manager.delete('nope')).toBe(false);
    });
  });

  // --- Persistence ---

  describe('persistence', () => {
    it('should persist snippets to disk and reload', async () => {
      await manager.save({
        name: 'persistent',
        content: 'secret-data',
        description: 'Should survive reload',
        tags: ['test'],
      });

      // Create new manager from same dir
      const manager2 = new SnippetManager(tmpDir);
      await manager2.init();

      const meta = manager2.getMeta('persistent');
      expect(meta).toBeDefined();
      expect(meta!.description).toBe('Should survive reload');

      const full = manager2.getContent('persistent');
      expect(full!.content).toBe('secret-data');
    });

    it('should persist deletions', async () => {
      await manager.save({ name: 'gone', content: 'bye', description: 'Will be deleted' });
      await manager.delete('gone');

      const manager2 = new SnippetManager(tmpDir);
      await manager2.init();
      expect(manager2.getMeta('gone')).toBeUndefined();
    });

    it('should handle empty/missing file gracefully', async () => {
      const emptyDir = await fs.mkdtemp(path.join(os.tmpdir(), 'snippet-empty-'));
      const m = new SnippetManager(emptyDir);
      await m.init(); // Should not throw
      expect(m.list()).toHaveLength(0);
      await fs.rm(emptyDir, { recursive: true, force: true });
    });
  });

  // --- Security: metadata never leaks content ---

  describe('security - content isolation', () => {
    it('getMeta must never include content field', async () => {
      await manager.save({
        name: 'secret-key',
        content: 'SUPER_SECRET_API_KEY_12345',
        description: 'Very secret key',
      });

      const meta = manager.getMeta('secret-key');
      const keys = Object.keys(meta!);
      expect(keys).not.toContain('content');
    });

    it('list must never include content field', async () => {
      await manager.save({
        name: 's1',
        content: 'secret1',
        description: 'd1',
      });
      await manager.save({
        name: 's2',
        content: 'secret2',
        description: 'd2',
      });

      const list = manager.list();
      list.forEach(item => {
        expect(Object.keys(item)).not.toContain('content');
      });
    });

    it('save return value must not include content', async () => {
      const result = await manager.save({
        name: 'test',
        content: 'hidden',
        description: 'desc',
      });
      expect(Object.keys(result)).not.toContain('content');
    });
  });
});
