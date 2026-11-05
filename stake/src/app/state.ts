import { useSyncExternalStore } from 'react';
import { browserMode } from '../data/runtime-mode';

export type View = 'overview' | 'findings' | 'attacks' | 'code' | 'remediation' | 'assessment';
export function routeQuery() { return browserMode ? (window.location.hash.startsWith('#?') ? window.location.hash.slice(1) : '') : window.location.search; }
export function readParams() { return new URLSearchParams(routeQuery()); }
export function routeHref(params: URLSearchParams | string) {
  const query = typeof params === 'string' ? params.replace(/^\?/, '') : params.toString();
  return window.location.pathname + (query ? (browserMode ? '#?' : '?') + query : '');
}
export function replaceReportRoute(params = new URLSearchParams({ view: 'overview' })) {
  window.history.replaceState({}, '', routeHref(params));
  window.dispatchEvent(new PopStateEvent('popstate'));
}
function subscribe(listener: () => void) {
  window.addEventListener('popstate', listener);
  window.addEventListener('hashchange', listener);
  return () => { window.removeEventListener('popstate', listener); window.removeEventListener('hashchange', listener); };
}
export function useRoute() {
  const query = useSyncExternalStore(subscribe, routeQuery);
  const params = new URLSearchParams(query);
  const value = (key: string, fallback = '') => params.get(key) ?? fallback;
  function navigate(changes: Record<string, string | null>, replace = false) {
    const next = readParams();
    Object.entries(changes).forEach(([key, val]) => val ? next.set(key, val) : next.delete(key));
    const url = routeHref(next);
    if (url === routeHref(readParams())) return;
    window.history[replace ? 'replaceState' : 'pushState']({}, '', url);
    window.dispatchEvent(new PopStateEvent('popstate'));
  }
  return { params, value, navigate };
}
export class ApiError extends Error {
  constructor(message: string, public status: number, public code?: string, public fieldErrors?: Partial<Record<'ordinaryPath' | 'advantagePath', string>>) { super(message); }
}
export async function readJson<T>(response: Response, generation?: string): Promise<T> {
  if (!response.ok) {
    let message = 'The requested record is unavailable.';
    let code: string | undefined;
    let fieldErrors: ApiError['fieldErrors'];
    try { const body = await response.json(); message = body.error ?? body.message ?? message; code = body.code; fieldErrors = body.fieldErrors; } catch { /* no raw response */ }
    throw new ApiError(message, response.status, code, fieldErrors);
  }
  if (generation && response.headers.get('X-Stake-Workspace') !== generation) throw new ApiError('The workspace changed. Reloading the current reports…', 409, 'workspace_changed');
  return response.json() as Promise<T>;
}
export async function getJson<T>(url: string, signal?: AbortSignal, generation?: string): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (generation) headers['X-Stake-Workspace'] = generation;
  return readJson<T>(await fetch(url, { signal, headers }), generation);
}
export function human(value: unknown): string {
  if (value === null || value === undefined || value === '') return 'Unknown';
  return String(value).replaceAll('_', ' ');
}
export function dateLabel(value: string | null | undefined): string {
  if (!value) return 'Unknown';
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeZone: 'UTC' }).format(date) + ' UTC';
}
