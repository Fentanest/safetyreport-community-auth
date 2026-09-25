export const PORTS: { pg: number; auth: number; rest: number; gateway: number; kakao: number; site: number };
export function loadStackEnv(): Record<string, string>;
export function psql(sql: string, options?: { user?: string; env?: Record<string, string>; tuplesOnly?: boolean }): string;
