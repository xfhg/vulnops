import { TextReader, Uint8ArrayWriter, ZipWriter } from '@zip.js/zip.js';
import { makeFinding, makePublication } from './bundles';
export async function makeBrowserZip(options: { broken?: boolean; suffix?: string; zero?: boolean } = {}) {
  const writer = new ZipWriter(new Uint8ArrayWriter(), { useWebWorkers: false });
  for (const kind of ['audit', 'advantage'] as const) {
    const finding = makeFinding({ title: 'Synthetic repair journey ' + (options.suffix ?? kind) });
    finding.technical_examples!.push({ id: 'source-example', kind: 'source', content: 'SYNTHETIC_REPAIR_SOURCE\nauthorize_order(account, order);', execution_status: 'not_executed', evidence_refs: ['storefront/src/orders.ts:42'] });
    finding.remediation!.actions[0].example_ids!.push('source-example');
    const publication = makePublication({ kind, runId: `${kind}-fixture`, findings: options.zero ? [] : [finding] });
    const files: Record<string, string> = {
      'report/security-report.json': JSON.stringify(publication.report),
      'report/security-report.md': publication.markdown,
      'final-verification/findings.json': JSON.stringify(publication.final),
      'sast/verified-findings.json': JSON.stringify([{ id: 'C-001', explanation: `SYNTHETIC_EVIDENCE_${kind}` }]),
    };
    if (options.broken && kind === 'advantage') delete files['report/security-report.md'];
    for (const [name, content] of Object.entries(files)) await writer.add(`wrapper/${kind} folder/${name}`, new TextReader(content));
  }
  return { name: `synthetic${options.suffix ?? ''}.zip`, mimeType: 'application/zip', buffer: Buffer.from(await writer.close()) };
}
