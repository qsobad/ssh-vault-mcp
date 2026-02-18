/**
 * Snippet Manager
 * Manages code snippets, notes, and reusable commands.
 * Content is sensitive (may contain API keys etc.) — reading content requires user approval.
 */

import { promises as fs } from 'fs';
import path from 'path';
import crypto from 'crypto';

export interface Snippet {
  id: string;
  name: string;
  content: string;          // Stored but NOT returned without approval
  description: string;      // Always visible — helps agent know what's inside
  tags: string[];
  language?: string;        // "bash", "python", "sql", "text", etc.
  createdAt: number;
  updatedAt: number;
}

export interface SnippetMeta {
  id: string;
  name: string;
  description: string;
  tags: string[];
  language?: string;
  createdAt: number;
  updatedAt: number;
}

export interface SnippetStore {
  version: 1;
  snippets: Snippet[];
}

export class SnippetManager {
  private store: SnippetStore = { version: 1, snippets: [] };
  private filePath: string;
  constructor(dataDir: string) {
    this.filePath = path.join(dataDir, 'snippets.json');
  }

  async init(): Promise<void> {
    try {
      const data = await fs.readFile(this.filePath, 'utf-8');
      this.store = JSON.parse(data);
    } catch {
      // File doesn't exist yet — start fresh
      this.store = { version: 1, snippets: [] };
    }
  }

  private async persist(): Promise<void> {
    await fs.mkdir(path.dirname(this.filePath), { recursive: true });
    await fs.writeFile(this.filePath, JSON.stringify(this.store, null, 2));
  }

  async save(params: {
    name: string;
    content: string;
    description: string;
    tags?: string[];
    language?: string;
  }): Promise<SnippetMeta> {
    const existing = this.store.snippets.find(s => s.name === params.name);
    const now = Date.now();

    if (existing) {
      existing.content = params.content;
      existing.description = params.description;
      if (params.tags !== undefined) existing.tags = params.tags;
      if (params.language !== undefined) existing.language = params.language;
      existing.updatedAt = now;
      await this.persist();
      return this.toMeta(existing);
    }

    const snippet: Snippet = {
      id: crypto.randomUUID(),
      name: params.name,
      content: params.content,
      description: params.description,
      tags: params.tags || [],
      language: params.language || 'text',
      createdAt: now,
      updatedAt: now,
    };
    this.store.snippets.push(snippet);
    await this.persist();
    return this.toMeta(snippet);
  }

  /** Get full snippet (including content) — caller must enforce approval */
  getContent(name: string): Snippet | undefined {
    return this.store.snippets.find(s => s.name === name);
  }

  /** Get metadata only (no content) — safe without approval */
  getMeta(name: string): SnippetMeta | undefined {
    const s = this.store.snippets.find(s => s.name === name);
    return s ? this.toMeta(s) : undefined;
  }

  list(filter?: { tags?: string[]; language?: string; query?: string }): SnippetMeta[] {
    let results = this.store.snippets;

    if (filter?.tags?.length) {
      results = results.filter(s =>
        filter.tags!.some(t => s.tags.includes(t))
      );
    }
    if (filter?.language) {
      results = results.filter(s => s.language === filter.language);
    }
    if (filter?.query) {
      const q = filter.query.toLowerCase();
      results = results.filter(s =>
        s.name.toLowerCase().includes(q) ||
        s.description.toLowerCase().includes(q) ||
        s.tags.some(t => t.toLowerCase().includes(q))
      );
    }

    return results.map(s => this.toMeta(s));
  }

  async delete(name: string): Promise<boolean> {
    const idx = this.store.snippets.findIndex(s => s.name === name);
    if (idx === -1) return false;
    this.store.snippets.splice(idx, 1);
    await this.persist();
    return true;
  }

  private toMeta(s: Snippet): SnippetMeta {
    return {
      id: s.id,
      name: s.name,
      description: s.description,
      tags: s.tags,
      language: s.language,
      createdAt: s.createdAt,
      updatedAt: s.updatedAt,
    };
  }
}
