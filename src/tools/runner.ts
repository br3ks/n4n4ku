import pLimit from "p-limit";

export interface ParallelOptions<T, R> {
  items: T[];
  concurrency?: number;
  workerFn: (item: T) => Promise<R | null>;
  onStart?: (total: number, concurrency: number) => void;
  onProgress?: (completed: number, total: number, currentItem: T, result: R | null) => void;
}

export async function runParallelWithProgress<T, R>(
  options: ParallelOptions<T, R>
): Promise<R[]> {
  const {
    items,
    concurrency = 20,
    workerFn,
    onStart,
    onProgress,
  } = options;

  const total = items.length;
  if (total === 0) return [];

  onStart?.(total, concurrency);

  const limit = pLimit(concurrency);
  let completed = 0;

  const tasks = items.map((item) =>
    limit(async () => {
      try {
        const result = await workerFn(item);
        completed++;
        onProgress?.(completed, total, item, result);
        return result;
      } catch {
        completed++;
        onProgress?.(completed, total, item, null);
        return null;
      }
    })
  );

  const rawResults = await Promise.all(tasks);
  const filtered: R[] = [];
  for (const res of rawResults) {
    if (res !== null && res !== undefined) {
      filtered.push(res as R);
    }
  }
  return filtered;
}

