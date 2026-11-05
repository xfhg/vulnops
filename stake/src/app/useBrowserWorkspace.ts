import { useEffect, useRef, useSyncExternalStore } from 'react';
import { BrowserCoordinator } from '../data/browser-coordinator';
import { readParams, replaceReportRoute, routeQuery } from './state';
import type { SourcePair, SourceSubmissionResult } from '../domain/sources';
import { matchesBrowserDestination } from './browser-destination';

let instance: BrowserCoordinator | undefined;
function coordinator() { return instance ??= new BrowserCoordinator(); }

export function useBrowserWorkspace() {
  const dataSource = coordinator();
  const snapshot = useSyncExternalStore(dataSource.subscribe, dataSource.getSnapshot);
  const prior = useRef<{ generation: string; loaded: boolean } | null>(null);
  const initialQuery = useRef(routeQuery());
  const initialNavigation = useRef(false);
  useEffect(() => {
    const track = () => { if (routeQuery() !== initialQuery.current) initialNavigation.current = true; };
    window.addEventListener('popstate', track); window.addEventListener('hashchange', track);
    void dataSource.initialize();
    return () => { window.removeEventListener('popstate', track); window.removeEventListener('hashchange', track); };
  }, [dataSource]);
  useEffect(() => {
    if (snapshot.phase === 'restoring') return;
    const old = prior.current;
    const loaded = Boolean(snapshot.workspace?.assessments.length);
    prior.current = { generation: snapshot.generation, loaded };
    if (!old || old.generation === snapshot.generation) return;
    // A first import may satisfy the link that brought this browser here.
    const params = readParams();
    const pendingInitial = !old.loaded && loaded && !initialNavigation.current && initialQuery.current === routeQuery();
    const controller = new AbortController();
    const query = routeQuery();
    const finish = (retain: boolean) => {
      if (controller.signal.aborted || dataSource.getSnapshot().generation !== snapshot.generation) return;
      // Explicit navigation during a pending lookup wins. Do not reset the
      // user's newer destination after a late projection/page result arrives.
      if (pendingInitial && (initialNavigation.current || routeQuery() !== query)) return;
      if (!retain) replaceReportRoute();
      initialNavigation.current = true;
      requestAnimationFrame(() => {
        if (controller.signal.aborted || dataSource.getSnapshot().generation !== snapshot.generation) return;
        const heading = document.querySelector<HTMLElement>('#main h1') ?? document.getElementById('main');
        heading?.setAttribute('tabindex', '-1'); heading?.focus();
      });
    };
    if (pendingInitial) void matchesBrowserDestination(params, snapshot.workspace!, dataSource, controller.signal).then(finish);
    else finish(false);
    return () => controller.abort();
  }, [snapshot.generation, snapshot.phase, snapshot.workspace]);
  return {
    dataSource, workspace: snapshot.workspace, sources: null,
    loadError: '', busy: Boolean(snapshot.progress) || snapshot.phase === 'restoring', notice: '',
    ownCompletion: snapshot.ownCompletion, refresh: () => dataSource.refresh(),
    loadSources: async (_pair: SourcePair, _generation: string): Promise<SourceSubmissionResult> => ({ status: 'failed', message: 'Select a ZIP in this browser.' }),
    browser: snapshot,
    importArchive: (file: File, generation: string) => dataSource.importArchive(file, file.name, generation),
    removeArchive: (generation: string) => { initialNavigation.current = true; return dataSource.remove(generation); },
    cancelImport: () => dataSource.cancelImport(),
  };
}
