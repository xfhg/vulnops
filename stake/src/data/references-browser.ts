import type { Workspace } from '../domain/types';
import { artifactSizeLimit, parseArtifactJson, validatePublicationContent } from './archive/hygiene';
import { ArchiveError } from './archive/types';
import { SharedEvidenceRegistry, type EvidenceBundle } from './references';
import { selectEvidenceValue } from './references-select';

export type { EvidenceBundle, EvidenceResult, ReferenceEntry } from './references';
export type EvidenceTextReader = (root: string, path: string, limit?: number) => Promise<string>;

/** Only registered, owning-execution references can reach the admitted ZIP reader. */
export function createBrowserEvidenceRegistry(bundles: EvidenceBundle[], workspace: Workspace, generation: string, readText: EvidenceTextReader): SharedEvidenceRegistry {
  return new SharedEvidenceRegistry(bundles, workspace, generation, {
    // Handles are opaque and local to this registry. Replacing/restoring the ZIP
    // constructs a new registry; tokens can never resolve against another one.
    createToken: () => crypto.randomUUID(),
    async readArtifact(bundle, path) {
      const limit = artifactSizeLimit(path);
      const text = await readText(bundle.inputPath, path, limit ?? undefined);
      if (path.endsWith('.json')) {
        const content = parseArtifactJson(text, path);
        if (content !== null && typeof content === 'object' && !Array.isArray(content) && Object.hasOwn(content, 'run_id') && (content as Record<string, unknown>).run_id !== bundle.run_id)
          throw new ArchiveError('denied', 'Artifact belongs to a different execution.');
        return { content, format: 'json' };
      }
      validatePublicationContent(text, limit);
      return { content: text, format: 'text' };
    },
    selectArtifact: (value, reference) => ({ content: selectEvidenceValue(value, reference), format: 'json' }),
    describeError: error => ({
      denied: error instanceof ArchiveError && ['denied', 'invalid_content'].includes(error.code),
      message: error instanceof ArchiveError ? error.message : 'Evidence could not be read.',
    }),
  });
}
