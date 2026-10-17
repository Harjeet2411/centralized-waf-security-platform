// Same-origin API client. The browser never holds AWS credentials: it talks only to FastAPI, authenticated by the
// HttpOnly session cookie (CLAUDE.md constraint #3). In dev, Vite proxies /api and /ws to localhost:8000.
import { QueryClient } from '@tanstack/react-query';

export class ApiError extends Error {
  status: number;
  detail: unknown;

  constructor(status: number, detail: unknown) {
    super(ApiError.describe(status, detail));
    this.status = status;
    this.detail = detail;
  }

  static describe(status: number, detail: unknown): string {
    if (typeof detail === 'string') return detail;
    if (detail && typeof detail === 'object' && 'message' in detail) {
      const d = detail as { message: string; protected?: { name: string; category: string }[] };
      const names = d.protected?.map(p => `${p.name} (${p.category})`).join(', ');
      return names ? `${d.message}: ${names}` : d.message;
    }
    if (Array.isArray(detail)) return detail.map(e => (e as { msg?: string }).msg ?? String(e)).join('; ');
    return `Request failed (${status})`;
  }
}

export async function api<T>(path: string, init: RequestInit & { json?: unknown } = {}): Promise<T> {
  const { json, headers, ...rest } = init;
  const response = await fetch(path, {
    credentials: 'include',
    ...rest,
    headers: { Accept: 'application/json', ...(json !== undefined ? { 'Content-Type': 'application/json' } : {}), ...headers },
    body: json !== undefined ? JSON.stringify(json) : rest.body,
  });
  const text = await response.text();
  const body = text ? JSON.parse(text) : null;
  if (!response.ok) throw new ApiError(response.status, body?.detail ?? body);
  return body as T;
}

export const loginUrl = '/api/v1/auth/login';

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      refetchOnWindowFocus: false,
      retry: (failures, error) =>
        !(error instanceof ApiError && [401, 403, 404, 422].includes(error.status)) && failures < 2,
    },
  },
});

export interface PlatformEvent {
  type: 'SYNC_STARTED' | 'SYNC_COMPLETED' | 'APPROVAL_REQUESTED' | 'APPROVAL_UPDATED' | string;
  payload: Record<string, unknown>;
  at: string;
}

/** Subscribe to /ws/events with exponential-backoff reconnects. Returns an unsubscribe function. */
export function connectEvents(onEvent: (event: PlatformEvent) => void): () => void {
  let socket: WebSocket | null = null;
  let closed = false;
  let delay = 1_000;
  let timer: ReturnType<typeof setTimeout> | undefined;

  const open = () => {
    const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws';
    socket = new WebSocket(`${scheme}://${window.location.host}/ws/events`);
    socket.onopen = () => { delay = 1_000; };
    socket.onmessage = msg => {
      try { onEvent(JSON.parse(msg.data)); } catch { /* ignore malformed frames */ }
    };
    socket.onclose = () => {
      if (closed) return;
      timer = setTimeout(open, delay);
      delay = Math.min(delay * 2, 30_000);
    };
  };
  open();
  return () => {
    closed = true;
    clearTimeout(timer);
    socket?.close();
  };
}
