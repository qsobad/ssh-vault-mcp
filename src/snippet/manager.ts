/**
 * Snippet Manager
 * Manages code snippets, notes, and reusable commands stored in the vault.
 * Snippets can be used as agent notes or fed to SSH for execution.
 */

export interface Snippet {
  id: string;
  name: string;
  content: string;
  description?: string;
  tags: string[];
  language?: string;       // "bash", "python", "sql", "text", etc.
  createdAt: number;
  updatedAt: number;
}

export interface SnippetStore {
  snippets: Snippet[];
}

export class SnippetManager {
  private store: SnippetStore = { snippets: [] };

  constructor(initialData?: SnippetStore) {
    if (initialData) {
      this.store = initialData;
    }
  }

  getStore(): SnippetStore {
    return this.store;
  }

  save(params: {
    name: string;
    content: string;
    description?: string;
    tags?: string[];
    language?: string;
  }): Snippet {
    const existing = this.store.snippets.find(s => s.name === params.name);
    const now = Date.now();

    if (existing) {
      existing.content = params.content;
      if (params.description !== undefined) existing.description = params.description;
      if (params.tags !== undefined) existing.tags = params.tags;
      if (params.language !== undefined) existing.language = params.language;
      existing.updatedAt = now;
      return existing;
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
    return snippet;
  }

  get(name: string): Snippet | undefined {
    return this.store.snippets.find(s => s.name === name);
  }

  getById(id: string): Snippet | undefined {
    return this.store.snippets.find(s => s.id === id);
  }

  list(filter?: { tags?: string[]; language?: string; query?: string }): Snippet[] {
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
        (s.description?.toLowerCase().includes(q)) ||
        s.content.toLowerCase().includes(q)
      );
    }

    return results;
  }

  delete(name: string): boolean {
    const idx = this.store.snippets.findIndex(s => s.name === name);
    if (idx === -1) return false;
    this.store.snippets.splice(idx, 1);
    return true;
  }
}
