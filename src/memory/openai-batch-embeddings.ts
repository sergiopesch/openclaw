import {
  OPENAI_BATCH_ENDPOINT,
  type OpenAiBatchRequest,
  runOpenAiEmbeddingBatches,
} from "./batch-openai.js";
import type { OpenAiEmbeddingClient } from "./embeddings.js";
import { hashText, type MemoryChunk, type MemoryFileEntry } from "./internal.js";
import type { SessionFileEntry } from "./session-files.js";

type MemorySource = "memory" | "sessions";

export async function embedChunksWithOpenAiBatch(params: {
  chunks: MemoryChunk[];
  entry: MemoryFileEntry | SessionFileEntry;
  source: MemorySource;
  openAi?: OpenAiEmbeddingClient;
  providerModel: string;
  agentId: string;
  batch: {
    wait: boolean;
    concurrency: number;
    pollIntervalMs: number;
    timeoutMs: number;
  };
  loadEmbeddingCache: (hashes: string[]) => Map<string, number[]>;
  upsertEmbeddingCache: (entries: Array<{ hash: string; embedding: number[] }>) => void;
  runBatchWithFallback: <T>(params: {
    provider: string;
    run: () => Promise<T>;
    fallback: () => Promise<number[][]>;
  }) => Promise<T | number[][]>;
  fallback: () => Promise<number[][]>;
  debug: (message: string, data?: Record<string, unknown>) => void;
}): Promise<number[][]> {
  const openAi = params.openAi;
  if (!openAi) {
    return await params.fallback();
  }
  if (params.chunks.length === 0) {
    return [];
  }

  const cached = params.loadEmbeddingCache(params.chunks.map((chunk) => chunk.hash));
  const embeddings: number[][] = Array.from({ length: params.chunks.length }, () => []);
  const missing: Array<{ index: number; chunk: MemoryChunk }> = [];

  for (let i = 0; i < params.chunks.length; i += 1) {
    const chunk = params.chunks[i];
    const hit = chunk?.hash ? cached.get(chunk.hash) : undefined;
    if (hit && hit.length > 0) {
      embeddings[i] = hit;
    } else if (chunk) {
      missing.push({ index: i, chunk });
    }
  }

  if (missing.length === 0) {
    return embeddings;
  }

  const requests: OpenAiBatchRequest[] = [];
  const mapping = new Map<string, { index: number; hash: string }>();
  for (const item of missing) {
    const chunk = item.chunk;
    const customId = hashText(
      `${params.source}:${params.entry.path}:${chunk.startLine}:${chunk.endLine}:${chunk.hash}:${item.index}`,
    );
    mapping.set(customId, { index: item.index, hash: chunk.hash });
    requests.push({
      custom_id: customId,
      method: "POST",
      url: OPENAI_BATCH_ENDPOINT,
      body: {
        model: openAi.model ?? params.providerModel,
        input: chunk.text,
      },
    });
  }

  const batchResult = await params.runBatchWithFallback({
    provider: "openai",
    run: async () =>
      await runOpenAiEmbeddingBatches({
        openAi,
        agentId: params.agentId,
        requests,
        wait: params.batch.wait,
        concurrency: params.batch.concurrency,
        pollIntervalMs: params.batch.pollIntervalMs,
        timeoutMs: params.batch.timeoutMs,
        debug: (message, data) =>
          params.debug(message, { ...data, source: params.source, chunks: params.chunks.length }),
      }),
    fallback: params.fallback,
  });

  if (Array.isArray(batchResult)) {
    return batchResult;
  }
  const byCustomId = batchResult;

  const toCache: Array<{ hash: string; embedding: number[] }> = [];
  for (const [customId, embedding] of byCustomId.entries()) {
    const mapped = mapping.get(customId);
    if (!mapped) {
      continue;
    }
    embeddings[mapped.index] = embedding;
    toCache.push({ hash: mapped.hash, embedding });
  }
  params.upsertEmbeddingCache(toCache);
  return embeddings;
}
