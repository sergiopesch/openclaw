import type { DatabaseSync } from "node:sqlite";

import type {
  EmbeddingProvider,
  GeminiEmbeddingClient,
  OpenAiEmbeddingClient,
} from "./embeddings.js";
import type { MemoryChunk } from "./internal.js";
import { hashText, parseEmbedding } from "./internal.js";

const EMBEDDING_BATCH_MAX_TOKENS = 8000;
const EMBEDDING_APPROX_CHARS_PER_TOKEN = 1;
const EMBEDDING_QUERY_TIMEOUT_REMOTE_MS = 60_000;
const EMBEDDING_QUERY_TIMEOUT_LOCAL_MS = 5 * 60_000;
const EMBEDDING_BATCH_TIMEOUT_REMOTE_MS = 2 * 60_000;
const EMBEDDING_BATCH_TIMEOUT_LOCAL_MS = 10 * 60_000;

export function estimateEmbeddingTokens(text: string): number {
  if (!text) {
    return 0;
  }
  return Math.ceil(text.length / EMBEDDING_APPROX_CHARS_PER_TOKEN);
}

export function buildEmbeddingBatches(chunks: MemoryChunk[]): MemoryChunk[][] {
  const batches: MemoryChunk[][] = [];
  let current: MemoryChunk[] = [];
  let currentTokens = 0;

  for (const chunk of chunks) {
    const estimate = estimateEmbeddingTokens(chunk.text);
    const wouldExceed = current.length > 0 && currentTokens + estimate > EMBEDDING_BATCH_MAX_TOKENS;
    if (wouldExceed) {
      batches.push(current);
      current = [];
      currentTokens = 0;
    }
    if (current.length === 0 && estimate > EMBEDDING_BATCH_MAX_TOKENS) {
      batches.push([chunk]);
      continue;
    }
    current.push(chunk);
    currentTokens += estimate;
  }

  if (current.length > 0) {
    batches.push(current);
  }
  return batches;
}

export function loadEmbeddingCache(params: {
  db: DatabaseSync;
  table: string;
  cacheEnabled: boolean;
  providerId: string;
  providerModel: string;
  providerKey: string;
  hashes: string[];
}): Map<string, number[]> {
  if (!params.cacheEnabled || params.hashes.length === 0) {
    return new Map();
  }
  const unique: string[] = [];
  const seen = new Set<string>();
  for (const hash of params.hashes) {
    if (!hash || seen.has(hash)) {
      continue;
    }
    seen.add(hash);
    unique.push(hash);
  }
  if (unique.length === 0) {
    return new Map();
  }

  const out = new Map<string, number[]>();
  const baseParams = [params.providerId, params.providerModel, params.providerKey];
  const batchSize = 400;
  for (let start = 0; start < unique.length; start += batchSize) {
    const batch = unique.slice(start, start + batchSize);
    const placeholders = batch.map(() => "?").join(", ");
    const rows = params.db
      .prepare(
        `SELECT hash, embedding FROM ${params.table}\n` +
          ` WHERE provider = ? AND model = ? AND provider_key = ? AND hash IN (${placeholders})`,
      )
      .all(...baseParams, ...batch) as Array<{ hash: string; embedding: string }>;
    for (const row of rows) {
      out.set(row.hash, parseEmbedding(row.embedding));
    }
  }
  return out;
}

export function upsertEmbeddingCache(params: {
  db: DatabaseSync;
  table: string;
  cacheEnabled: boolean;
  providerId: string;
  providerModel: string;
  providerKey: string;
  entries: Array<{ hash: string; embedding: number[] }>;
}): void {
  if (!params.cacheEnabled || params.entries.length === 0) {
    return;
  }
  const now = Date.now();
  const stmt = params.db.prepare(
    `INSERT INTO ${params.table} (provider, model, provider_key, hash, embedding, dims, updated_at)\n` +
      ` VALUES (?, ?, ?, ?, ?, ?, ?)\n` +
      ` ON CONFLICT(provider, model, provider_key, hash) DO UPDATE SET\n` +
      `   embedding=excluded.embedding,\n` +
      `   dims=excluded.dims,\n` +
      `   updated_at=excluded.updated_at`,
  );
  for (const entry of params.entries) {
    const embedding = entry.embedding ?? [];
    stmt.run(
      params.providerId,
      params.providerModel,
      params.providerKey,
      entry.hash,
      JSON.stringify(embedding),
      embedding.length,
      now,
    );
  }
}

export function pruneEmbeddingCacheIfNeeded(params: {
  db: DatabaseSync;
  table: string;
  cacheEnabled: boolean;
  maxEntries?: number;
}): void {
  if (!params.cacheEnabled) {
    return;
  }
  const max = params.maxEntries;
  if (!max || max <= 0) {
    return;
  }
  const row = params.db.prepare(`SELECT COUNT(*) as c FROM ${params.table}`).get() as
    | { c: number }
    | undefined;
  const count = row?.c ?? 0;
  if (count <= max) {
    return;
  }
  const excess = count - max;
  params.db
    .prepare(
      `DELETE FROM ${params.table}\n` +
        ` WHERE rowid IN (\n` +
        `   SELECT rowid FROM ${params.table}\n` +
        `   ORDER BY updated_at ASC\n` +
        `   LIMIT ?\n` +
        ` )`,
    )
    .run(excess);
}

export function computeProviderKey(params: {
  provider: EmbeddingProvider;
  openAi?: OpenAiEmbeddingClient;
  gemini?: GeminiEmbeddingClient;
}): string {
  if (params.provider.id === "openai" && params.openAi) {
    const entries = Object.entries(params.openAi.headers)
      .filter(([key]) => key.toLowerCase() !== "authorization")
      .toSorted(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => [key, value]);
    return hashText(
      JSON.stringify({
        provider: "openai",
        baseUrl: params.openAi.baseUrl,
        model: params.openAi.model,
        headers: entries,
      }),
    );
  }
  if (params.provider.id === "gemini" && params.gemini) {
    const entries = Object.entries(params.gemini.headers)
      .filter(([key]) => {
        const lower = key.toLowerCase();
        return lower !== "authorization" && lower !== "x-goog-api-key";
      })
      .toSorted(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => [key, value]);
    return hashText(
      JSON.stringify({
        provider: "gemini",
        baseUrl: params.gemini.baseUrl,
        model: params.gemini.model,
        headers: entries,
      }),
    );
  }
  return hashText(JSON.stringify({ provider: params.provider.id, model: params.provider.model }));
}

export function isRetryableEmbeddingError(message: string): boolean {
  return /(rate[_ ]limit|too many requests|429|resource has been exhausted|5\d\d|cloudflare)/i.test(
    message,
  );
}

export function isBatchTimeoutError(message: string): boolean {
  return /timed out|timeout/i.test(message);
}

export function resolveEmbeddingTimeout(providerId: string, kind: "query" | "batch"): number {
  const isLocal = providerId === "local";
  if (kind === "query") {
    return isLocal ? EMBEDDING_QUERY_TIMEOUT_LOCAL_MS : EMBEDDING_QUERY_TIMEOUT_REMOTE_MS;
  }
  return isLocal ? EMBEDDING_BATCH_TIMEOUT_LOCAL_MS : EMBEDDING_BATCH_TIMEOUT_REMOTE_MS;
}

export async function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  message: string,
): Promise<T> {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    return await promise;
  }
  let timer: NodeJS.Timeout | null = null;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(message)), timeoutMs);
  });
  try {
    return (await Promise.race([promise, timeoutPromise])) as T;
  } finally {
    if (timer) {
      clearTimeout(timer);
    }
  }
}
