type BatchConfig = {
  enabled: boolean;
};

type Logger = {
  debug: (message: string, data?: Record<string, unknown>) => void;
  warn: (message: string, data?: Record<string, unknown>) => void;
};

export type BatchFailureSnapshot = {
  failures: number;
  lastError?: string;
  lastProvider?: string;
};

export class BatchFailureController {
  private failureCount = 0;
  private lastError?: string;
  private lastProvider?: string;
  private lock: Promise<void> = Promise.resolve();

  constructor(
    private readonly config: BatchConfig,
    private readonly limit: number,
    private readonly log: Logger,
    private readonly isBatchTimeoutError: (message: string) => boolean,
  ) {}

  snapshot(): BatchFailureSnapshot {
    return {
      failures: this.failureCount,
      lastError: this.lastError,
      lastProvider: this.lastProvider,
    };
  }

  private async withLock<T>(fn: () => Promise<T>): Promise<T> {
    let release: () => void;
    const wait = this.lock;
    this.lock = new Promise<void>((resolve) => {
      release = resolve;
    });
    await wait;
    try {
      return await fn();
    } finally {
      release!();
    }
  }

  private async reset(): Promise<void> {
    await this.withLock(async () => {
      if (this.failureCount > 0) {
        this.log.debug("memory embeddings: batch recovered; resetting failure count");
      }
      this.failureCount = 0;
      this.lastError = undefined;
      this.lastProvider = undefined;
    });
  }

  private async recordFailure(params: {
    provider: string;
    message: string;
    attempts?: number;
    forceDisable?: boolean;
  }): Promise<{ disabled: boolean; count: number }> {
    return await this.withLock(async () => {
      if (!this.config.enabled) {
        return { disabled: true, count: this.failureCount };
      }
      const increment = params.forceDisable ? this.limit : Math.max(1, params.attempts ?? 1);
      this.failureCount += increment;
      this.lastError = params.message;
      this.lastProvider = params.provider;
      const disabled = params.forceDisable || this.failureCount >= this.limit;
      if (disabled) {
        this.config.enabled = false;
      }
      return { disabled, count: this.failureCount };
    });
  }

  private async runWithTimeoutRetry<T>(params: {
    provider: string;
    run: () => Promise<T>;
  }): Promise<T> {
    try {
      return await params.run();
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (this.isBatchTimeoutError(message)) {
        this.log.warn(`memory embeddings: ${params.provider} batch timed out; retrying once`);
        try {
          return await params.run();
        } catch (retryErr) {
          (retryErr as { batchAttempts?: number }).batchAttempts = 2;
          throw retryErr;
        }
      }
      throw err;
    }
  }

  async runWithFallback<T>(params: {
    provider: string;
    run: () => Promise<T>;
    fallback: () => Promise<number[][]>;
  }): Promise<T | number[][]> {
    if (!this.config.enabled) {
      return await params.fallback();
    }
    try {
      const result = await this.runWithTimeoutRetry({
        provider: params.provider,
        run: params.run,
      });
      await this.reset();
      return result;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const attempts = (err as { batchAttempts?: number }).batchAttempts ?? 1;
      const forceDisable = /asyncBatchEmbedContent not available/i.test(message);
      const failure = await this.recordFailure({
        provider: params.provider,
        message,
        attempts,
        forceDisable,
      });
      const suffix = failure.disabled ? "disabling batch" : "keeping batch enabled";
      this.log.warn(
        `memory embeddings: ${params.provider} batch failed (${failure.count}/${this.limit}); ${suffix}; falling back to non-batch embeddings: ${message}`,
      );
      return await params.fallback();
    }
  }
}
