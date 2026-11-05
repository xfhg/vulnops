import { useEffect, useState } from 'react';
import { createHighlighterCore } from 'shiki/core';
import { createJavaScriptRegexEngine } from 'shiki/engine/javascript';
import { Check, Copy } from 'lucide-react';
import { Button, Badge } from './ui';
import type { TechnicalExample } from '../domain/types';
import { RecordView } from './RecordView';
import { human } from '../app/state';

// Red and neutral variants keep code text above 4.5:1 on the workspace surfaces.
// Unclassified tokens remain neutral; emphasis never implies evidence status.
function syntaxTheme(name: string, type: 'light' | 'dark', palette: {
  foreground: string; background: string; comment: string; keyword: string;
  literal: string; string: string; symbol: string; punctuation: string;
}) {
  return { name, type, colors: { 'editor.foreground': palette.foreground, 'editor.background': palette.background },
    tokenColors: [
      { settings: { foreground: palette.foreground, background: palette.background } },
      { scope: ['comment', 'punctuation.definition.comment'], settings: { foreground: palette.comment } },
      { scope: ['keyword', 'storage', 'entity.name.tag', 'support.type.property-name'], settings: { foreground: palette.keyword } },
      { scope: ['constant', 'support.constant'], settings: { foreground: palette.literal } },
      { scope: ['string', 'markup.raw', 'meta.embedded.assembly'], settings: { foreground: palette.string } },
      { scope: ['entity.name.function', 'entity.name.type', 'support.function', 'variable.parameter'], settings: { foreground: palette.symbol } },
      { scope: ['punctuation', 'keyword.operator'], settings: { foreground: palette.punctuation } },
      { scope: ['invalid', 'markup.deleted'], settings: { foreground: palette.keyword } },
      { scope: ['markup.inserted'], settings: { foreground: palette.foreground } },
    ] };
}
const lightTheme = syntaxTheme('stake-light', 'light', {
  foreground: '#171717', background: '#f0f0f0', comment: '#595959', keyword: '#830000',
  literal: '#6f4444', string: '#3f3f3f', symbol: '#bc0202', punctuation: '#595959',
});
const darkTheme = syntaxTheme('stake-dark', 'dark', {
  foreground: '#f5f5f5', background: '#151515', comment: '#b5b5b5', keyword: '#ff6666',
  literal: '#cda9a9', string: '#d0d0d0', symbol: '#e6baba', punctuation: '#b5b5b5',
});

const highlighter = createHighlighterCore({
  themes: [lightTheme, darkTheme],
  langs: [import('shiki/langs/json.mjs'), import('shiki/langs/java.mjs'), import('shiki/langs/javascript.mjs'), import('shiki/langs/bash.mjs'), import('shiki/langs/http.mjs'), import('shiki/langs/yaml.mjs')],
  engine: createJavaScriptRegexEngine(),
});
export default function CodeBlock({ example }: { example: TechnicalExample }) {
  const [html, setHtml] = useState('');
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState('');
  useEffect(() => {
    let active = true;
    const lang = example.kind === 'request' ? 'http' : example.kind === 'command' ? 'bash' : example.kind === 'configuration' ? 'yaml' : 'text';
    highlighter.then(h => { if (active) setHtml(h.codeToHtml(example.content, { lang, themes: { light: 'stake-light', dark: 'stake-dark' } })); }).catch(() => { if (active) setHtml(''); });
    return () => { active = false; };
  }, [example.content, example.kind]);
  async function copy() {
    try { await navigator.clipboard.writeText(example.content); setCopied(true); setCopyError(''); } catch { setCopyError('Select the example text to copy it.'); }
  }
  return <div className="code-example"><header><span className="mono">{example.id}</span><Badge>{human(example.execution_status)}</Badge><Button variant="ghost" size="sm" onClick={copy}>{copied ? <Check size={14} /> : <Copy size={14} />}{copied ? 'Copied' : 'Copy example'}</Button></header>
    {html ? <div className="code-content" dangerouslySetInnerHTML={{ __html: html }} /> : <pre className="code-content">{example.content}</pre>}
    {copyError && <p role="status">{copyError}</p>}
    {Boolean(example.substitutions?.length) && <details className="example-substitutions"><summary>Declared substitutions</summary><RecordView value={example.substitutions} /></details>}
  </div>;
}
