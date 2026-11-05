import { createHash, randomUUID } from 'node:crypto';
import type { Workspace } from '../src/domain/types.js';
import { SharedEvidenceRegistry } from '../src/data/references.js';
import type { ImportedBundle } from './admission.js';
import { bridgeCall, BridgeError, type BridgeOptions } from './bridge.js';

export type { ReferenceEntry, EvidenceResult } from '../src/data/references.js';

/** The HTTP reader retains its token format and existing Python read boundary. */
export class EvidenceRegistry extends SharedEvidenceRegistry {
  constructor(bundles: ImportedBundle[], workspace: Workspace, options: BridgeOptions = {}, generation: string = randomUUID()) {
    super(bundles, workspace, generation, {
      createToken: (generation, owner, reference) => createHash('sha256').update(JSON.stringify([generation, owner, reference])).digest('base64url'),
      readArtifact: (bundle, path) => bridgeCall({ operation: 'evidence', root: bundle.inputPath, reference: path, executionId: bundle.run_id }, options),
      selectArtifact: (value, reference) => bridgeCall({ operation: 'select', reference, value }, options),
      describeError: error => ({
        denied: error instanceof BridgeError && ['denied', 'invalid_content'].includes(error.code),
        message: error instanceof BridgeError ? error.message : 'Evidence could not be read.',
      }),
    });
  }
}
