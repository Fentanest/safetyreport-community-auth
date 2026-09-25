import type { Server } from 'node:http';
export function startMockKakao(options?: { port?: number; clientSecret?: string; clientId?: string; redirectUri?: string }): Promise<Server>;
export function followOAuth(authorizeUrl: string, choice?: string): Promise<URL>;
