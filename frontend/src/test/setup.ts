// Vitest setup — extends expect with jest-dom matchers (toBeInTheDocument…).
import "@testing-library/jest-dom/vitest";

// jsdom in this vitest config does not expose `localStorage` (the Storage API
// is disabled in the default environment), yet every api helper touches it via
// getAuthToken(). Provide a minimal in-memory implementation so components
// that call the api layer can render under test. `configurable` keeps
// per-test vi.stubGlobal overrides possible.
const _store = new Map<string, string>();
Object.defineProperty(globalThis, "localStorage", {
  value: {
    getItem: (k: string): string | null => (_store.has(k) ? _store.get(k)! : null),
    setItem: (k: string, v: string): void => {
      _store.set(k, String(v));
    },
    removeItem: (k: string): void => {
      _store.delete(k);
    },
    clear: (): void => {
      _store.clear();
    },
    key: (i: number): string | null => [..._store.keys()][i] ?? null,
    get length(): number {
      return _store.size;
    },
  },
  configurable: true,
});
