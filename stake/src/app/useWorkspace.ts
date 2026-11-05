import { useCallback, useEffect, useRef, useState } from 'react';
import type { SourcePair, SourceSubmissionResult, WorkspaceResponse, WorkspaceSourceState, WorkspaceVersion } from '../domain/sources';
import { ApiError, replaceReportRoute } from './state';
import { httpDataSource } from '../data/http';
import { browserMode } from '../data/runtime-mode';
import { useBrowserWorkspace } from './useBrowserWorkspace';

interface WorkspaceFrame { workspace: WorkspaceResponse; sources: WorkspaceSourceState }
interface Submission { generation: string; lastLoadId: string | null; acceptedLoadId?: string; uncertain: boolean }

function resetReportRoute() {
  replaceReportRoute();
}

/** One generation owns every report view. Source drafts live outside that lifetime. */
function useServerWorkspace() {
  const [frame, setFrame] = useState<WorkspaceFrame | null>(null);
  const [loadError, setLoadError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [notice, setNotice] = useState('');
  const [ownCompletion, setOwnCompletion] = useState(0);
  const current = useRef<WorkspaceFrame | null>(null);
  const pending = useRef<Submission | null>(null);
  const mounted = useRef(true);
  const sequence = useRef(0);
  const refreshController = useRef<AbortController | null>(null);
  const submitController = useRef<AbortController | null>(null);

  const refresh = useCallback(async () => {
    const ticket = ++sequence.current;
    refreshController.current?.abort();
    const controller = new AbortController();
    refreshController.current = controller;
    try {
      // A commit can occur between these bootstrap reads. Never combine generations.
      for (let attempt = 0; attempt < 3; attempt++) {
        const [workspace, sources] = await Promise.all([
          httpDataSource.workspace(controller.signal),
          httpDataSource.sources(controller.signal),
        ]);
        if (!mounted.current || ticket !== sequence.current || controller.signal.aborted) return null;
        if (workspace.generation !== sources.generation) continue;
        const previous = current.current;
        const changed = Boolean(previous && previous.sources.generation !== sources.generation);
        const submission = pending.current;
        // The POST response proves this submission committed. Another tab may
        // already have begun or completed a later load before this refresh.
        const finishedOwnLoad = Boolean(submission?.acceptedLoadId && sources.generation !== submission.generation);
        if (changed) {
          resetReportRoute();
          setNotice('');
        }
        if (finishedOwnLoad) {
          pending.current = null;
          setSubmitting(false);
          setOwnCompletion(value => value + 1);
          setNotice(sources.lastLoad?.status === 'failed' ? sources.lastLoad.message : '');
        } else if (submission?.uncertain && !sources.loading) {
          pending.current = null;
          setSubmitting(false);
          setNotice(sources.lastLoad?.id !== submission.lastLoadId && sources.lastLoad
            ? sources.lastLoad.status === 'failed' ? sources.lastLoad.message : ''
            : 'The load response was interrupted. Current sources have been refreshed; review them before trying again.');
        }
        const next = { workspace, sources };
        current.current = next;
        setFrame(next);
        setLoadError('');
        if (changed) requestAnimationFrame(() => {
          if (!mounted.current) return;
          const heading = document.querySelector<HTMLElement>('#main h1');
          heading?.setAttribute('tabindex', '-1');
          heading?.focus();
        });
        return next;
      }
      throw new Error('Reports changed while loading. Checking the current workspace again…');
    } catch (error) {
      if (!controller.signal.aborted && mounted.current && ticket === sequence.current) setLoadError(error instanceof Error ? error.message : 'Workspace unavailable.');
      return null;
    }
  }, []);

  const loadSources = useCallback(async (pair: SourcePair, expectedGeneration: string): Promise<SourceSubmissionResult> => {
    if (pending.current || current.current?.sources.loading) return { status: 'pending', message: 'A report load is already in progress.' };
    if (current.current?.sources.generation !== expectedGeneration) return { status: 'failed', message: 'The workspace changed. Use current sources before loading another pair.' };
    pending.current = { generation: expectedGeneration, lastLoadId: current.current.sources.lastLoad?.id ?? null, uncertain: false };
    setSubmitting(true);
    setNotice('Loading reports… You can close Settings while this finishes.');
    const controller = new AbortController();
    submitController.current = controller;
    try {
      const accepted = await httpDataSource.loadSources(pair, expectedGeneration, controller.signal);
      if (pending.current) pending.current.acceptedLoadId = accepted.lastLoad?.id;
      const latest = await refresh();
      if (latest && latest.sources.generation !== expectedGeneration) return { status: 'loaded' };
      return { status: 'pending', message: 'Checking the loaded workspace…' };
    } catch (error) {
      if (!mounted.current) return { status: 'pending' };
      if (error instanceof ApiError) {
        pending.current = null;
        setSubmitting(false);
        setNotice(error.message);
        await refresh();
        return { status: 'failed', message: error.message, fieldErrors: error.fieldErrors };
      }
      if (pending.current) pending.current.uncertain = true;
      setNotice('Connection interrupted. Checking whether the reports finished loading…');
      const latest = await refresh();
      if (latest && latest.sources.generation !== expectedGeneration) {
        setNotice(latest.sources.lastLoad?.status === 'failed' ? latest.sources.lastLoad.message : '');
        return { status: 'loaded' };
      }
      return { status: latest && !latest.sources.loading ? 'failed' : 'pending', message: 'The load response was interrupted. Check the current source status before trying again.' };
    }
  }, [refresh]);

  useEffect(() => {
    mounted.current = true;
    void refresh();
    const pollController = new AbortController();
    let checking = false;
    async function check() {
      if (document.visibilityState === 'hidden' || checking) return;
      checking = true;
      try {
        const version = await httpDataSource.version(pollController.signal);
        const state = current.current?.sources;
        if (!state || version.generation !== state.generation || version.loading !== state.loading || version.lastLoadId !== (state.lastLoad?.id ?? null) || pending.current) await refresh();
      } catch { /* A temporary disconnect keeps the current view; the next visible check reconciles it. */ }
      finally { checking = false; }
    }
    const timer = window.setInterval(() => void check(), 5000);
    window.addEventListener('focus', check);
    document.addEventListener('visibilitychange', check);
    return () => {
      mounted.current = false;
      ++sequence.current;
      refreshController.current?.abort();
      submitController.current?.abort();
      pollController.abort();
      clearInterval(timer);
      window.removeEventListener('focus', check);
      document.removeEventListener('visibilitychange', check);
    };
  }, [refresh]);

  return { browser: null, importArchive: async (_file: File, _generation: string) => {}, removeArchive: async (_generation: string) => {}, cancelImport: () => {}, dataSource: httpDataSource, workspace: frame?.workspace ?? null, sources: frame?.sources ?? null, loadError, busy: submitting || Boolean(frame?.sources.loading), notice, ownCompletion, refresh, loadSources };
}

/** Build selection is fixed for the lifetime of the application. */
export function useWorkspace(): ReturnType<typeof useBrowserWorkspace> | ReturnType<typeof useServerWorkspace> {
  return browserMode ? useBrowserWorkspace() : useServerWorkspace();
}
