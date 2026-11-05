import ELK from 'elkjs/lib/elk.bundled.js';
import { layoutGraph, type LayoutRequest } from './layout';

const elk = new ELK();
globalThis.onmessage = async (event: MessageEvent<LayoutRequest>) => {
  const { requestId } = event.data;
  try {
    const layout = await layoutGraph(event.data, elk);
    globalThis.postMessage({ requestId, ...layout });
  } catch {
    globalThis.postMessage({ requestId, error: 'Automatic layout unavailable. The complete linear view remains available.' });
  }
};
