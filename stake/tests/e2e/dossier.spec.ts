import { expect, test, type Locator, type Page } from '@playwright/test';
import type { FindingRecord } from '../../src/domain';

const findingKey = JSON.stringify(['finding', 'audit-fixture', 'F-001']);
const longEntrypoint = 'The fulfillment consumer accepts a recorded approval handoff from the order service after the caller selects an order belonging to a synthetic account. The entrypoint label describes the complete handoff and its caller-controlled input; it is a recorded sentence rather than an inferred HTTP route.';
const secondEntrypoint = 'A second recorded consumer processes the same approval identity inside the synthetic storefront assessment.';
const mechanism = 'The reviewed operation consumes the selected identity without establishing ownership of the target order. ' + 'The source citation retains this boundary condition and its original assessment context. '.repeat(6).trim();
const additionalContext = 'Additional synthetic component context remains available without changing the displayed entrypoint labels.';
const change = 'Bind the session to its initiating account and authorize the selected order before approval.';
const secondAction = 'Request approval of another synthetic account’s order.';
const narrativeAccess = 'A normal customer session can supply the synthetic approval reference through the recorded callback. ' + 'The caller has no authorized access to the other account’s order. '.repeat(4) + 'The complete starting-access record ends here.';
const narrativeMechanism = 'The identity granted at the first step is consumed without an object ownership check. ' + 'The recorded handler accepts the selected approval identity before establishing the target account boundary. '.repeat(4) + 'The complete mechanism record ends here.';
const narrativeImpact = 'An order belonging to another synthetic account can be approved. ' + 'The source assessment establishes the unauthorized approval within the recorded preconditions. '.repeat(4) + 'The complete impact record ends here.';
const intendedBehavior = 'Only the authenticated owner or an explicitly authorized reviewer may approve the order.';

async function openDossier(page: Page, panel: 'summary' | 'reproduce' | 'repair', narrow = false) {
  await page.route('**/api/findings/*', async route => {
    const response = await route.fetch();
    const finding = await response.json() as FindingRecord;
    if (finding.id === 'F-001') {
      const first = finding.raw.affected_components![0];
      first.entrypoints = ['POST /orders/approve', longEntrypoint];
      const second = structuredClone(first);
      second.id = 'component-2';
      second.name = 'Fulfillment consumer';
      second.entrypoints = [secondEntrypoint];
      second.viewer_note = additionalContext;
      if (narrow) second.repository = 'storefront/' + 'long-fulfillment-namespace-'.repeat(7) + 'consumer';
      delete second.service;
      finding.raw.affected_components!.push(second);
      finding.raw.root_causes![0].mechanism = mechanism;
      finding.raw.remediation!.actions[0].locations![0].mechanism = mechanism;
      finding.raw.remediation!.actions[0].component_ids = ['component-1', 'component-2'];
      if (panel === 'summary') {
        finding.raw.attacker!.starting_access = narrativeAccess;
        finding.raw.exploitation!.rationale = narrativeMechanism;
        finding.raw.impact = narrativeImpact;
      }
      // One condition intentionally repeats setup, allowing the layout to account for it explicitly.
      finding.raw.conditions!.push(finding.raw.exploitation!.setup![0]);
    }
    await route.fulfill({ response, json: finding });
  });
  await page.goto('/?' + new URLSearchParams({ view: 'findings', finding: findingKey, mode: 'procedure', panel }));
  await expect(page.locator('.finding-detail')).toBeVisible();
  await expect(page.getByRole('region', { name: 'Attack explorer', exact: true })).toHaveCount(0);
}

async function noOverflow(page: Page) {
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
}

async function capturePanelViewport(page: Page, panel: string) {
  await page.getByRole('tablist', { name: 'Finding detail', exact: true }).evaluate(node => node.scrollIntoView({ block: 'start' }));
  await page.evaluate(() => window.scrollBy(0, -88));
  await page.screenshot({ path: `/private/tmp/atstake-${panel}-desktop-viewport.png` });
}

async function expandRecordedExplanation(page: Page, summary: Locator) {
  const explanation = summary.getByRole('list', { name: 'Recorded finding explanation', exact: true });
  await expect(explanation.locator(':scope > li')).toHaveCount(4);
  await expect(explanation.locator('[data-slot="trace-line"]')).toHaveCount(4);
  await expect(explanation.locator('[data-status]')).toHaveCount(0);
  const access = explanation.getByRole('button', { name: 'Starting access and prerequisites', exact: true });
  const boundary = explanation.getByRole('button', { name: 'Why the boundary fails', exact: true });
  const impact = explanation.getByRole('button', { name: 'Impact and limits', exact: true });
  await expect(boundary).toHaveAttribute('aria-expanded', 'true');
  await boundary.click();
  for (const trigger of [access, boundary, impact]) {
    await expect(trigger).toHaveAttribute('aria-expanded', 'false');
    await expect(trigger.locator('.summary-trace-preview')).toBeVisible();
    await expect(trigger.locator('button')).toHaveCount(0);
  }
  await access.focus();
  await page.keyboard.press('Enter');
  await expect(access).toHaveAttribute('aria-expanded', 'true');
  await expect(explanation.locator('.summary-access-facts dd').nth(1)).toHaveText(narrativeAccess);
  await expect(access.locator('.summary-trace-preview')).toBeHidden();
  await page.keyboard.press('Tab');
  await expect(boundary).toBeFocused();
  await page.keyboard.press('Space');
  await expect(boundary).toHaveAttribute('aria-expanded', 'true');
  await expect(explanation.locator('.summary-boundary-grid>div').nth(0).locator('p')).toHaveText(intendedBehavior);
  await expect(explanation.locator('.summary-boundary-grid>div').nth(1).locator('p')).toHaveText(narrativeMechanism);
  await page.keyboard.press('Tab');
  await expect(impact).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(impact).toHaveAttribute('aria-expanded', 'true');
  await expect(explanation.locator('.summary-impact')).toHaveText(narrativeImpact);
  await expect(explanation.locator('.summary-limits')).toContainText('No deployed environment was exercised.');
  await expect(explanation.locator('[data-status]')).toHaveCount(0);
  const supporting = explanation.getByRole('button', { name: 'Supporting source citations', exact: true });
  await expect(supporting).toHaveAttribute('aria-expanded', 'false');
  await supporting.click();
  await expect(supporting).toHaveAttribute('aria-expanded', 'true');
  await expect(explanation.getByRole('table', { name: 'Root-cause locations', exact: true })).toBeVisible();
  return explanation;
}

test('summary inventory preserves complete component entrypoints, service context and source access', async ({ page }) => {
  await openDossier(page, 'summary');
  const summary = page.locator('.finding-summary-panel');
  const explanation = await expandRecordedExplanation(page, summary);
  await explanation.screenshot({ path: '/private/tmp/atstake-trace-expanded-desktop.png' });
  for (const title of ['Starting access and prerequisites', 'Why the boundary fails', 'Impact and limits']) {
    const trigger = explanation.getByRole('button', { name: title, exact: true });
    await trigger.focus();
    await page.keyboard.press('Space');
    await expect(trigger).toHaveAttribute('aria-expanded', 'false');
    await expect(trigger.locator('.summary-trace-preview')).toBeVisible();
  }
  const components = summary.locator('.summary-component-item');
  await expect(components).toHaveCount(2);
  await expect(summary.locator('.summary-inventory-count')).toContainText('2 components');
  const first = components.nth(0);
  const second = components.nth(1);
  await expect(first.locator('.summary-component-trigger')).toHaveAttribute('aria-expanded', 'false');
  await first.locator('.summary-component-trigger').click();
  await expect(first.locator('.summary-component-trigger')).toHaveAttribute('aria-expanded', 'true');
  await expect(first.locator('.summary-component-counts')).toContainText('2 entrypoints');
  await expect(first.locator('.summary-entrypoints p')).toHaveText(['POST /orders/approve', longEntrypoint]);
  await expect.poll(() => first.locator('.summary-entrypoints p').nth(1).evaluate(node => node.scrollHeight <= node.clientHeight + 1 && node.scrollWidth <= node.clientWidth + 1)).toBe(true);
  await expect(first.locator('.summary-service-context')).toContainText('Deployment routing is not established.');
  await expect(first.locator('.summary-entrypoints')).not.toContainText('Deployment routing is not established.');

  const secondTrigger = second.locator('.summary-component-trigger');
  await expect(secondTrigger).toHaveAttribute('aria-expanded', 'false');
  await secondTrigger.focus();
  await page.keyboard.press('Enter');
  await expect(secondTrigger).toHaveAttribute('aria-expanded', 'true');
  await expect(second.locator('.summary-entrypoints p')).toHaveText(secondEntrypoint);
  await expect(second.locator('.summary-service-context')).toContainText('No service binding recorded');
  await second.getByText('Complete component record', { exact: true }).click();
  await expect(second.getByText(additionalContext, { exact: true })).toBeVisible();
  await second.getByText('Complete component record', { exact: true }).click();

  const roots = summary.getByRole('table', { name: 'Root-cause locations', exact: true });
  await roots.locator('.dossier-source-context summary').click();
  await expect(roots.locator('.dossier-source-context')).toHaveAttribute('open', '');
  await expect(roots.locator('.dossier-source-context>div .dossier-copy')).toHaveText(mechanism);
  await roots.getByRole('button', { name: 'storefront/src/orders.ts:42', exact: true }).click();
  await expect(page.getByRole('dialog')).toContainText('storefront/src/orders.ts:42');
  await expect(page.getByRole('dialog')).not.toContainText('This reference is not registered');
  await page.keyboard.press('Escape');
  await noOverflow(page);
  await summary.screenshot({ path: '/private/tmp/atstake-summary-desktop.png' });
  await capturePanelViewport(page, 'summary');
});

test('reproduction keeps expected and observed effects distinct and supports keyboard example and instruction handoffs', async ({ page }) => {
  await openDossier(page, 'reproduce');
  const reproduce = page.locator('.reproduce-panel');
  const setup = reproduce.getByRole('region', { name: 'Setup and prerequisites', exact: true });
  await expect(setup.locator('.repro-checklist li')).toHaveCount(1);
  await expect(setup.locator('.repro-shared-requirements')).toContainText('1 condition is already included in the setup list');
  await expect(setup.getByRole('complementary', { name: 'Recorded actor and access' })).toContainText('Signed-in customer');
  await setup.getByRole('button', { name: 'Why this procedure works', exact: true }).click();
  await expect(setup).toContainText('The identity granted at the first step is consumed without an object ownership check.');
  const steps = reproduce.locator('.procedure-card');
  await expect(steps).toHaveCount(2);
  await expect.poll(() => steps.evaluateAll(cards => cards.every(card => {
    const width = card.getBoundingClientRect().width;
    const sections = card.querySelectorAll(':scope > .repro-step-header, :scope > .repro-step-body, :scope > .repro-step-footer');
    return sections.length === 3 && [...sections].every(section => {
      const sectionWidth = section.getBoundingClientRect().width;
      return sectionWidth >= width - 4 && sectionWidth <= width + 1;
    });
  }))).toBe(true);
  await expect(steps.nth(0).locator('.repro-effect-expected')).toContainText('A session identity is selected.');
  await expect(steps.nth(0).locator('.repro-effect-observed')).toContainText('No observation recorded; no execution claimed.');
  await expect(steps.nth(0).locator('.repro-step-context')).toContainText('Storefront');

  await steps.nth(0).getByRole('button', { name: 'View example example-1', exact: true }).focus();
  await page.keyboard.press('Enter');
  const example = reproduce.getByRole('region', { name: 'Recorded technical example example-1', exact: true });
  await expect(example).toBeFocused();
  await expect(example).toContainText('SYNTHETIC_ORDER');
  await expect(example).toContainText('not executed');
  await noOverflow(page);
  await reproduce.screenshot({ path: '/private/tmp/atstake-reproduce-desktop.png' });
  await capturePanelViewport(page, 'reproduce');

  await example.getByRole('button', { name: 'step-2', exact: true }).focus();
  await page.keyboard.press('Enter');
  expect(JSON.parse(new URL(page.url()).searchParams.get('detailRecord')!)).toEqual(['step', 'step-2']);
  await expect(reproduce.getByRole('region', { name: secondAction, exact: true })).toBeFocused();
  await expect(page.getByRole('region', { name: 'Attack explorer', exact: true })).toHaveCount(0);
  await expect(page.getByRole('tab', { name: /^Reproduce/ })).toHaveAttribute('data-state', 'active');
  await steps.nth(0).getByRole('button', { name: 'Read repair action-1', exact: true }).click();
  await expect(page.getByRole('tab', { name: /^Repair/ })).toHaveAttribute('data-state', 'active');
  expect(new URL(page.url()).searchParams.get('repair')).toBe('action-1');
  await expect(page.locator('.repair-implementation-card[data-repair-id="action-1"]')).toBeFocused();
});

test('repair cards lead with the control change and retain source context, exact interruptions and verification handoff', async ({ page }) => {
  await openDossier(page, 'repair');
  const repair = page.locator('.repair-panel');
  const action = repair.locator('.repair-implementation-card');
  await expect(action).toHaveCount(1);
  await expect(action.getByRole('heading', { level: 3 })).toHaveText(change);
  await expect(action.locator('.repair-action-identity')).toContainText('action-1');
  await expect(action.locator('.repair-components')).toContainText('Fulfillment consumer');
  const locations = action.getByRole('region', { name: 'Repair location orders.ts:42', exact: true });
  await expect(locations).toContainText('orders.ts');
  await expect(locations).toContainText('Line 42');
  await expect(locations.locator('.repair-location-context p')).toHaveText(mechanism);
  await expect(locations.locator('.repair-location-context p')).toBeVisible();
  await expect(action.locator('.repair-step-link')).toHaveCount(2);
  await noOverflow(page);
  await repair.screenshot({ path: '/private/tmp/atstake-repair-desktop.png' });
  await capturePanelViewport(page, 'repair');

  await action.getByRole('button', { name: 'Show interruption', exact: true }).click();
  expect(new URL(page.url()).searchParams.get('repair')).toBe('action-1');
  await expect(page.getByRole('tab', { name: 'Attack map', exact: true })).toHaveAttribute('data-state', 'active');
  await expect(page.locator('.graph-evidence-node.repair-highlight')).toHaveCount(2);
  await page.getByRole('tab', { name: /^Repair/ }).click();
  await expect(action.getByRole('button', { name: 'Show interruption', exact: true })).toBeVisible();
  await action.locator('.repair-step-link').nth(1).focus();
  await page.keyboard.press('Enter');
  expect(JSON.parse(new URL(page.url()).searchParams.get('detailRecord')!)).toEqual(['step', 'step-2']);
  await expect(page.locator('.reproduce-panel').getByRole('region', { name: secondAction, exact: true })).toBeFocused();
  await expect(page.getByRole('tab', { name: /^Reproduce/ })).toHaveAttribute('data-state', 'active');
  await page.getByRole('tab', { name: /^Repair/ }).click();
  await repair.getByRole('button', { name: 'Review verification checks', exact: true }).click();
  await expect(page.getByRole('tab', { name: 'Verify', exact: true })).toHaveAttribute('data-state', 'active');
  const verification = page.getByRole('region', { name: 'Fix verification', exact: true });
  await expect(verification.getByRole('heading', { level: 2, name: 'Fix verification', exact: true })).toBeInViewport();
  await expect(verification).toContainText('The unauthorized approval is rejected without mutation.');
  await expect(verification).toContainText('The authorized approval succeeds.');
  await expect(verification).toContainText('proposed');
});

test('all dossier panels wrap long recorded prose and component identities on a narrow dark screen', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript(() => localStorage.setItem('stake-theme', 'dark'));
  await openDossier(page, 'summary', true);
  await expect(page.locator('html')).toHaveClass('dark');
  const summary = page.locator('.finding-summary-panel');
  const explanation = await expandRecordedExplanation(page, summary);
  await expect.poll(() => explanation.locator('.ui-trace-title, .summary-access-facts dd, .summary-boundary-grid p, .summary-impact').evaluateAll(nodes => nodes.every(node => node.scrollWidth <= node.clientWidth + 1 && node.scrollHeight <= node.clientHeight + 1))).toBe(true);
  await expect.poll(() => explanation.locator('.ui-trace-content').first().evaluate(node => getComputedStyle(node).animationName)).toBe('none');
  await noOverflow(page);
  await explanation.screenshot({ path: '/private/tmp/atstake-trace-expanded-mobile.png' });
  await summary.locator('.summary-component-trigger').nth(0).click();
  await summary.locator('.summary-component-trigger').nth(1).click();
  await expect(summary.locator('.summary-entrypoints p')).toHaveText(['POST /orders/approve', longEntrypoint, secondEntrypoint]);
  await noOverflow(page);
  await summary.screenshot({ path: '/private/tmp/atstake-summary-mobile.png' });

  await page.getByRole('tab', { name: /^Reproduce/ }).click();
  const reproduce = page.locator('.reproduce-panel');
  await expect(reproduce.locator('.procedure-card')).toHaveCount(2);
  await expect(reproduce.getByRole('region', { name: 'Recorded technical example example-1', exact: true })).toContainText('not executed');
  await noOverflow(page);
  await reproduce.screenshot({ path: '/private/tmp/atstake-reproduce-mobile.png' });

  await page.getByRole('tab', { name: /^Repair/ }).click();
  const repair = page.locator('.repair-panel');
  await expect(repair.getByRole('region', { name: 'Repair location orders.ts:42', exact: true }).locator('.repair-location-context p')).toBeVisible();
  await expect(repair.locator('.repair-components')).toContainText('long-fulfillment-namespace-');
  await noOverflow(page);
  await repair.screenshot({ path: '/private/tmp/atstake-repair-mobile.png' });
});
