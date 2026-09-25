import type { Server } from 'node:http';
export function startStaticServer(options: { root: string; port: number }): Promise<{ server: Server; log: { method: string; path: string; hasQuery: boolean }[] }>;
