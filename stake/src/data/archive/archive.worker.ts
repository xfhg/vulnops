import { openArchiveInProcess } from './reader';
import { safeArchiveError, type ArchiveSession } from './types';

type Request = { id: number; operation: 'open'; blob: Blob } | { id: number; operation: 'read'; root: string; path: string; limit?: number };
const port = self as unknown as { onmessage: ((event: MessageEvent<Request>) => void) | null; postMessage(value: unknown): void };
let session: ArchiveSession | undefined;
port.onmessage = async event => {
  const request = event.data;
  try {
    if (request.operation === 'open') {
      session?.dispose();
      session = await openArchiveInProcess(request.blob, undefined, progress => port.postMessage({ id: request.id, progress }));
      port.postMessage({ id: request.id, value: { bundles: session.bundles, workspace: session.workspace } });
    } else {
      if (!session) throw new Error('No admitted archive');
      port.postMessage({ id: request.id, value: await session.readText(request.root, request.path, request.limit) });
    }
  } catch (error) {
    const safe = safeArchiveError(error);
    port.postMessage({ id: request.id, error: { code: safe.code, message: safe.message } });
  }
};
