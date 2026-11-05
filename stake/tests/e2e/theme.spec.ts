import { expect, test, type Locator, type Page } from '@playwright/test';
import type { FindingRecord, TechnicalExample } from '../../src/domain';

const findingKey = JSON.stringify(['finding', 'audit-fixture', 'F-001']);
const brandPalette = { '--brand-black': '#000000', '--brand-blood': '#830000', '--brand-crimson': '#bc0202', '--brand-red': '#ff0000', '--brand-primary': '#ff1d58', '--primary': '#ff1d58', '--primary-foreground': '#171717' };
const palettes = {
  light: { '--bg': '#f7f7f7', '--panel': '#ffffff', '--panel-soft': '#f0f0f0', '--text': '#171717', '--muted-foreground': '#595959', '--accent': '#bc0202', '--primary-text': '#bb1242', '--primary-soft': '#fff0f4' },
  dark: { '--bg': '#0a0a0a', '--panel': '#151515', '--panel-soft': '#202020', '--text': '#f5f5f5', '--muted-foreground': '#b5b5b5', '--accent': '#ff6666', '--primary-text': '#ff5b86', '--primary-soft': '#251018' },
} as const;
type Theme = keyof typeof palettes;

/** WCAG relative luminance, using computed paints rather than source CSS literals.
 * Background and opacity are composed from the element through all ancestors.
 * Linear gradients are sampled at the element's corners and center; other
 * images are reported explicitly rather than treated as white.
 */
async function contrast(locator: Locator, label: string, minimum = 4.5, property = 'color') {
  const result = await locator.evaluateAll((elements, { minimum, property }) => {
    type Color = [number, number, number, number];
    const canvas = document.createElement('canvas');
    canvas.width = canvas.height = 1;
    const context = canvas.getContext('2d', { willReadFrequently: true })!;
    function color(value: string): Color {
      context.clearRect(0, 0, 1, 1);
      context.fillStyle = 'transparent';
      context.fillStyle = value === 'none' ? 'transparent' : value;
      context.fillRect(0, 0, 1, 1);
      const data = context.getImageData(0, 0, 1, 1).data;
      return [data[0], data[1], data[2], data[3] / 255];
    }
    function over(foreground: Color, background: Color): Color {
      const alpha = foreground[3] + background[3] * (1 - foreground[3]);
      if (!alpha) return [0, 0, 0, 0];
      return [0, 1, 2].map(index => (foreground[index] * foreground[3] + background[index] * background[3] * (1 - foreground[3])) / alpha).concat(alpha) as Color;
    }
    function luminance(value: Color) {
      const channels = value.slice(0, 3).map(channel => {
        const normalized = channel / 255;
        return normalized <= .04045 ? normalized / 12.92 : ((normalized + .055) / 1.055) ** 2.4;
      });
      return .2126 * channels[0] + .7152 * channels[1] + .0722 * channels[2];
    }
    function splitGradient(value: string): string[] {
      const parts: string[] = []; let depth = 0, start = 0;
      for (let index = 0; index < value.length; index++) {
        if (value[index] === '(') depth++;
        if (value[index] === ')') depth--;
        if (value[index] === ',' && !depth) { parts.push(value.slice(start, index).trim()); start = index + 1; }
      }
      parts.push(value.slice(start).trim()); return parts;
    }
    function gradient(value: string, bounds: DOMRect, point: { x: number; y: number }): Color | null {
      if (!value.startsWith('linear-gradient(')) return null;
      const parts = splitGradient(value.slice('linear-gradient('.length, -1));
      let angle = 180;
      if (/^-?[\d.]+deg$/.test(parts[0])) angle = Number.parseFloat(parts.shift()!);
      else if (parts[0].startsWith('to ') || parts[0].startsWith('in ')) return null;
      const stops = parts.map((part, index) => {
        const match = part.match(/^(.*)\s+(-?[\d.]+)%$/);
        return { color: color(match ? match[1] : part), position: match ? Number(match[2]) / 100 : index / (parts.length - 1) };
      });
      if (stops.length < 2) return null;
      const radians = angle * Math.PI / 180;
      const dx = Math.sin(radians), dy = -Math.cos(radians);
      const length = Math.abs(bounds.width * dx) + Math.abs(bounds.height * dy);
      const position = .5 + ((point.x - bounds.left - bounds.width / 2) * dx + (point.y - bounds.top - bounds.height / 2) * dy) / length;
      if (position <= stops[0].position) return stops[0].color;
      for (let index = 1; index < stops.length; index++) if (position <= stops[index].position) {
        const before = stops[index - 1], after = stops[index];
        const fraction = (position - before.position) / (after.position - before.position);
        const alpha = before.color[3] * (1 - fraction) + after.color[3] * fraction;
        return [0, 1, 2].map(channel => alpha ? (before.color[channel] * before.color[3] * (1 - fraction) + after.color[channel] * after.color[3] * fraction) / alpha : 0).concat(alpha) as Color;
      }
      return stops.at(-1)!.color;
    }
    const failures: Array<{ element: string; foreground: string; background: string; ratio: number }> = [];
    const nonFlatSurfaces = new Set<string>();
    let tested = 0;
    for (const element of elements) {
      const bounds = element.getBoundingClientRect();
      const style = getComputedStyle(element);
      if ((!bounds.width && !bounds.height) || style.visibility !== 'visible' || style.display === 'none' || element.closest('[disabled], [aria-disabled="true"]')) continue;
      if (property === 'color' && !element.textContent?.trim()) continue;
      const ancestry: Array<{ style: CSSStyleDeclaration; bounds: DOMRect }> = [];
      for (let current: Element | null = element; current; current = current.parentElement) ancestry.push({ style: getComputedStyle(current), bounds: current.getBoundingClientRect() });
      if (ancestry.some(({ style }) => Number(style.opacity) === 0 || style.visibility !== 'visible')) continue;
      const name = `${element.tagName.toLowerCase()}.${String(element.getAttribute('class') ?? '').replaceAll(' ', '.')} ${element.textContent?.trim().slice(0, 60) ?? ''}`;
      const foreground = color(style.getPropertyValue(property));
      if (property === 'stroke' || property === 'fill') foreground[3] *= Number(style.getPropertyValue(`${property}-opacity`) || 1);
      const edgeLabelBackground = element.classList.contains('react-flow__edge-text') ? element.parentElement?.querySelector('.react-flow__edge-textbg') : null;
      function rendered(ink: Color, point: { x: number; y: number }): Color {
        let paint = ink;
        if (edgeLabelBackground) paint = over(paint, color(getComputedStyle(edgeLabelBackground).fill));
        for (const layer of ancestry) {
          let background = color(layer.style.backgroundColor);
          if (layer.style.backgroundImage !== 'none' && paint[3] < 1) {
            const fill = gradient(layer.style.backgroundImage, layer.bounds, point);
            if (fill) background = over(fill, background);
            else nonFlatSurfaces.add(`${name}: ${layer.style.backgroundImage}`);
          }
          paint = over(paint, background);
          paint[3] *= Number(layer.style.opacity);
        }
        return over(paint, [255, 255, 255, 1]);
      }
      const samples = [{ x: bounds.left, y: bounds.top }, { x: bounds.right, y: bounds.top }, { x: bounds.left, y: bounds.bottom }, { x: bounds.right, y: bounds.bottom }, { x: bounds.left + bounds.width / 2, y: bounds.top + bounds.height / 2 }].map(point => {
        const text = rendered(foreground, point), surface = rendered([0, 0, 0, 0], point);
        return { text, surface, ratio: (Math.max(luminance(text), luminance(surface)) + .05) / (Math.min(luminance(text), luminance(surface)) + .05) };
      });
      const { text, surface, ratio } = samples.reduce((worst, sample) => sample.ratio < worst.ratio ? sample : worst);
      tested++;
      if (ratio < minimum) failures.push({ element: name, foreground: text.slice(0, 3).map(Math.round).join(','), background: surface.slice(0, 3).map(Math.round).join(','), ratio: Number(ratio.toFixed(3)) });
    }
    return { tested, failures, nonFlatSurfaces: [...nonFlatSurfaces] };
  }, { minimum, property });
  expect(result.tested, `${label}: at least one rendered paint must be measured`).toBeGreaterThan(0);
  expect.soft(result.nonFlatSurfaces, `${label}: every painted surface must be resolved`).toEqual([]);
  expect.soft(result.failures, `${label}: rendered contrast must be at least ${minimum}:1`).toEqual([]);
}

async function configure(page: Page, theme: Theme) {
  await page.addInitScript(theme => localStorage.setItem('stake-theme', theme), theme);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.route('**/api/findings/*', async route => {
    const response = await route.fetch();
    const finding = await response.json() as FindingRecord;
    if (finding.id === 'F-001') {
      const shared = { execution_status: 'not_executed', substitutions: [], evidence_refs: ['sast/verified-findings.json:C-001'], observation_refs: [] };
      const examples: TechnicalExample[] = [
        { ...shared, id: 'example-1', kind: 'request', content: 'POST /orders/approve HTTP/1.1\nContent-Type: application/json\nX-Synthetic-Flag: true\n\n{"order":"SYNTHETIC_ORDER","count":2}' },
        { ...shared, id: 'example-2', kind: 'command', content: '# Synthetic example; never executed\ncase "$MODE" in\n  preview) printf "%s\\n" "SYNTHETIC_ORDER" ;;\nesac\nCOUNT=2' },
        { ...shared, id: 'example-3', kind: 'configuration', content: '# Synthetic configuration\nservice: synthetic\ncount: 2\nenabled: true\nroute: "/orders/approve"\n' },
      ];
      finding.raw.technical_examples = examples;
    }
    await route.fulfill({ response, json: finding });
  });
}

async function checkPalette(page: Page, theme: Theme) {
  const expected = { ...brandPalette, ...palettes[theme] };
  const tokens = await page.locator('html').evaluate((element, expected) => {
    const probe = document.createElement('span');
    probe.style.display = 'none';
    element.appendChild(probe);
    const canvas = document.createElement('canvas');
    canvas.width = canvas.height = 1;
    const context = canvas.getContext('2d', { willReadFrequently: true })!;
    const resolve = (value: string): number[] | null => {
      if (!value || !CSS.supports('color', value)) return null;
      probe.style.color = '';
      probe.style.color = value;
      if (!probe.style.color) return null;
      context.clearRect(0, 0, 1, 1);
      context.fillStyle = getComputedStyle(probe).color;
      context.fillRect(0, 0, 1, 1);
      return Array.from(context.getImageData(0, 0, 1, 1).data);
    };
    try {
      const actual = Object.fromEntries(Object.keys(expected).map(name => [name, resolve(getComputedStyle(element).getPropertyValue(name).trim())]));
      return {
        actual,
        expected: Object.fromEntries(Object.entries(expected).map(([name, value]) => [name, resolve(value)])),
        invalid: Object.entries(actual).filter(([, value]) => value === null).map(([name]) => name),
      };
    } finally { probe.remove(); }
  }, expected);
  expect(tokens.invalid, 'Palette tokens must contain valid, nonempty CSS colors').toEqual([]);
  expect(tokens.actual).toEqual(tokens.expected);
  await contrast(page.locator('body'), `${theme} page text and page surface`);
}

async function checkBrand(page: Page) {
  await expect(page).toHaveTitle(/^VulnOps @stake/);
  await expect(page.getByRole('link', { name: 'VulnOps @stake home', exact: true })).toBeVisible();
  await expect(page.locator('.brand-name strong')).toHaveText('VulnOps');
  await expect(page.locator('.brand-name .brand-label')).toHaveText('@stake');
  const sizes = await page.locator('.brand-name').evaluate(element => ({
    primary: Number.parseFloat(getComputedStyle(element.querySelector('strong')!).fontSize),
    secondary: Number.parseFloat(getComputedStyle(element.querySelector('.brand-label')!).fontSize),
  }));
  expect(sizes.primary).toBeGreaterThanOrEqual(22);
  expect(sizes.secondary).toBeLessThanOrEqual(12);
  expect(sizes.primary / sizes.secondary).toBeGreaterThanOrEqual(1.8);
  await contrast(page.locator('.brand-name strong, .brand-name .brand-label, .nav-item, .nav-count, .sidebar-footer'), 'Brand, navigation and sidebar text');
}

async function graphContrast(page: Page, overview = false) {
  const root = overview ? page.locator('.ep-canvas') : page.locator('.graph-canvas');
  const labels = overview ? '.ep-node-kicker, .ep-node-title, .ep-node-caption, .ep-node-status, .ep-lane-heading span, .ep-lane-heading strong, .ep-lane-heading small, .ep-node-facts, .ep-capability-input, .ep-capability-label'
    : '.graph-node-meta, .graph-status, .graph-node-title, .graph-node-caption, .graph-node-fields dt, .graph-node-fields dd, .graph-node-footer';
  await contrast(root.locator(labels), `${overview ? 'Entrypoint' : 'Detailed'} graph card text`);
  await contrast(root.locator('.react-flow__edge-path'), 'Recorded graph edges', 3, 'stroke');
  // Overview labels deliberately collapse at atlas zoom. Selecting an edge
  // restores its callout, so measure the actual interactive presentation.
  if (overview) {
    await root.locator('.react-flow__edge').first().focus();
    await page.keyboard.press('Enter');
  }
  const svgLabels = root.locator('.react-flow__edge-text');
  const relationshipLabels = root.locator(overview ? '.ep-relation-label' : '.graph-transition-label');
  await expect.poll(async () => await svgLabels.count() + await relationshipLabels.count(), { message: 'Graph relationships have rendered labels' }).toBeGreaterThan(0);
  if (await svgLabels.count()) await contrast(svgLabels, 'Recorded sequence labels', 4.5, 'fill');
  if (await relationshipLabels.count()) await contrast(relationshipLabels, 'Graph relationship labels', 4.5);
  await contrast(root.locator('.graph-navigator-controls svg'), 'Graph control icons', 3, 'stroke');
  if (!overview) {
    const markers = await root.locator('.react-flow__edge-path').evaluateAll(paths => paths.map(path => {
      const reference = path.getAttribute('marker-end') ?? '';
      const url = reference.replace(/^url\(["']?/, '').replace(/["']?\)$/, '');
      const fragment = url.includes('#') ? url.slice(url.indexOf('#') + 1) : '';
      const marker = document.getElementById(fragment) ?? document.getElementById(decodeURIComponent(fragment));
      const shape = marker?.querySelector('polyline, polygon, path');
      return { resolved: Boolean(marker && shape), fill: shape ? getComputedStyle(shape).fill : null, stroke: getComputedStyle(path).stroke };
    }));
    expect(markers.length).toBeGreaterThan(0);
    for (const marker of markers) {
      expect(marker.resolved, 'Every arrowhead URL resolves to an SVG marker').toBe(true);
      expect(marker.fill, 'Arrowhead paint matches the measured edge stroke').toBe(marker.stroke);
    }
  }
}

for (const theme of ['light', 'dark'] as const) {
  test(`${theme} palette retains readable text, evidence, graph controls and code syntax across the workspace`, async ({ page }) => {
    await configure(page, theme);
    await page.goto('/');
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    await checkPalette(page, theme);
    await checkBrand(page);
    await contrast(page.locator('.assessment-overview h1, .assessment-overview h2, .assessment-overview h3, .assessment-overview p, .assessment-overview th, .assessment-overview td, .assessment-overview .metric-label, .assessment-overview .metric-foot, .assessment-overview .overview-metric-value, .assessment-overview .overview-metric-cue, .assessment-overview .badge, .assessment-overview button'), `${theme} overview headings, metrics, priority table and actions`);
    const repositoryBreakdown = page.getByRole('region', { name: 'Confirmed outcomes by repository', exact: true });
    await expect(repositoryBreakdown).toBeVisible();
    await contrast(repositoryBreakdown.locator('button, p, span, strong'), `${theme} repository counts and severity legend`);
    await contrast(page.locator('.overview-metric-icon svg'), `${theme} metric icon contrast`, 3, 'stroke');
    const featured = page.getByRole('button', { name: 'Explore high and critical outcomes', exact: true });
    await expect(featured.locator('.overview-metric-cue')).toHaveText('Prioritize');
    const hierarchy = await featured.evaluate(button => {
      const highlighted = button.querySelector('.overview-metric-value')!;
      const ordinary = document.querySelector('.overview-metric:not(.overview-metric-featured) .overview-metric-value')!;
      return { featured: parseFloat(getComputedStyle(highlighted).fontSize), ordinary: parseFloat(getComputedStyle(ordinary).fontSize), border: getComputedStyle(button.parentElement!).borderTopColor };
    });
    expect(hierarchy.featured).toBeGreaterThan(hierarchy.ordinary);
    expect(hierarchy.border).toBe('rgb(255, 29, 88)');
    await page.mouse.move(0, 0);
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: `/private/tmp/atstake-red-theme-${theme}-overview-desktop.png` });

    await page.goto('/?view=attacks');
    await expect(page.locator('.ep-canvas')).toHaveAttribute('data-layout-status', 'ready');
    await graphContrast(page, true);

    await page.goto('/?' + new URLSearchParams({ view: 'findings', finding: findingKey, mode: 'procedure', panel: 'graph' }));
    await expect(page.locator('.graph-evidence-node')).toHaveCount(2);
    await contrast(page.locator('.nav-item.active, .nav-item.active .nav-count'), `${theme} active Findings navigation and count`);
    await graphContrast(page);
    await contrast(page.locator('.finding-header h1, .finding-header .button, .finding-summary-text, .finding-header-facts dt, .finding-header-facts dd, .detail-badges .badge, .finding-journey-tabs .tabs-trigger, .graph-controls button, .graph-controls select, .graph-context-bar span'), `${theme} finding header and graph controls`);
    await page.getByRole('tab', { name: 'Summary', exact: true }).click();
    await contrast(page.locator('.finding-summary-panel p, .finding-summary-panel dt, .finding-summary-panel dd, .finding-summary-panel h4, .summary-component-trigger, .summary-trace-provenance, .summary-trace-copy .ui-trace-title, .summary-trace-preview, .dossier-source-link strong, .dossier-evidence strong, .dossier-evidence small'), `${theme} summary and source evidence`);
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: `/private/tmp/atstake-red-theme-${theme}-detail-desktop.png` });

    await page.getByRole('tab', { name: /^Reproduce/ }).click();
    await expect(page.locator('.code-content pre.shiki')).toHaveCount(3);
    await contrast(page.locator('.reproduce-panel .dossier-copy, .reproduce-panel .dossier-empty, .reproduce-panel dt, .reproduce-panel .badge, .reproduce-panel .button'), `${theme} reproduction evidence and actions`);
    await contrast(page.locator('.code-content .shiki, .code-content .shiki span[style]'), `${theme} HTTP, bash and YAML syntax`);
    const syntaxColors = await page.locator('.code-content .shiki span[style]').evaluateAll(spans => [...new Set(spans.filter(span => span.textContent?.trim()).map(span => getComputedStyle(span).color))]);
    expect(syntaxColors.length).toBeGreaterThanOrEqual(3);

    await page.getByRole('tab', { name: /^Repair/ }).click();
    await contrast(page.locator('.repair-panel p, .repair-panel h3, .repair-panel h4, .repair-panel .badge, .repair-step-link, .repair-panel .button, .repair-location-guide h5, .repair-location-guide h6, .repair-location-kicker, .repair-location-path code, .repair-location-excerpt-label, .repair-location-citations code'), `${theme} repair guidance and primary action`);
    await page.getByRole('button', { name: 'Show interruption', exact: true }).click();
    await expect(page.getByRole('tab', { name: 'Attack map', exact: true })).toHaveAttribute('data-state', 'active');
    await contrast(page.locator('.graph-evidence-node.repair-highlight .graph-node-title, .graph-repair-indicator, .graph-repair-summary, .graph-repair-location strong, .graph-repair-location small, .graph-repair-location code, .graph-read-repair'), `${theme} proposed repair overlay text`);
    await contrast(page.locator('.graph-evidence-node.repair-highlight'), `${theme} proposed repair overlay outline`, 3, 'border-top-color');
    await page.getByRole('tab', { name: /^Repair/ }).click();
    await page.getByRole('button', { name: 'Review verification checks', exact: true }).click();
    await contrast(page.locator('.verification-card h3, .verification-card h4, .verification-card p, .verification-card .badge'), `${theme} verification expectations and status`);
    await page.getByRole('tab', { name: 'Evidence', exact: true }).click();
    await contrast(page.locator('.dossier-stack dt, .dossier-stack dd, .dossier-stack .dossier-evidence strong, .dossier-stack .dossier-evidence small, .dossier-stack .dossier-source-link'), `${theme} provenance and evidence links`);

    await page.goto('/?view=code&run=audit-fixture');
    await expect(page.locator('.cg-node-location').first()).toBeVisible();
    await contrast(page.locator('.cg-node-kicker, .cg-node-title, .cg-node-caption, .cg-node-roles span, .cg-source-heading span, .cg-source-heading strong, .cg-source-heading small, .cg-inspector h4, .cg-inspector p, .cg-legend'), `${theme} code relationships and source context`);
    await contrast(page.locator('.cg-canvas .react-flow__edge-path'), `${theme} code citation and repair edges`, 3, 'stroke');
    await page.locator('.cg-canvas .react-flow__edge').first().focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('.cg-canvas .react-flow__edge-text')).toHaveCount(1);
    await contrast(page.locator('.cg-canvas .react-flow__edge-text'), `${theme} selected code relationship label`, 4.5, 'fill');

    await page.goto('/?view=assessment&run=advantage-fixture');
    await expect(page.locator('.asmt-workspace')).toBeVisible();
    await contrast(page.locator('.asmt-page-heading p, .asmt-identity-bar, .asmt-number-card span, .asmt-number-card small, .asmt-facts dt, .asmt-facts dd, .asmt-lineage p, .asmt-availability, .asmt-inline-action, .asmt-tabs .tabs-trigger'), `${theme} assessment scope, counts and actions`);
    await page.getByRole('tab', { name: 'Source scope', exact: true }).click();
    await contrast(page.locator('.asmt-repository-table th, .asmt-repository-table td, .asmt-scope-accordion .ui-accordion-trigger, .asmt-footnote p'), `${theme} source-scope metadata`);
    await page.getByRole('tab', { name: 'Evidence', exact: true }).click();
    await contrast(page.locator('.asmt-artifact-card p, .asmt-artifact-card .button, .asmt-checks-limit, .asmt-facts dt, .asmt-facts dd'), `${theme} original assessment evidence`);
  });

  test(`${theme} branding and finding surfaces remain readable on a narrow screen`, async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await configure(page, theme);
    await page.goto('/');
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    await checkPalette(page, theme);
    await page.getByRole('button', { name: 'Toggle navigation', exact: true }).click();
    await checkBrand(page);
    await page.getByRole('button', { name: 'Close navigation', exact: true }).click({ position: { x: 370, y: 200 } });
    await contrast(page.locator('.assessment-overview .metric-label, .assessment-overview .metric-foot, .assessment-overview .badge, .assessment-overview .priority-row p, .assessment-overview th, .assessment-overview td, .assessment-overview button'), `${theme} narrow overview text`);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: `/private/tmp/atstake-red-theme-${theme}-overview-mobile.png` });
    await page.goto('/?' + new URLSearchParams({ view: 'findings', finding: findingKey, mode: 'procedure', panel: 'reproduce' }));
    await expect(page.locator('.code-content pre.shiki')).toHaveCount(3);
    await contrast(page.locator('.finding-summary-text, .finding-header .button, .finding-header-facts dd, .detail-badges .badge, .finding-journey-tabs .tabs-trigger, .repro-effect dd, .reproduce-panel .button'), `${theme} narrow finding text and actions`);
    await contrast(page.locator('.code-content .shiki span[style]'), `${theme} narrow syntax`);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: `/private/tmp/atstake-red-theme-${theme}-detail-mobile.png` });
  });
}
