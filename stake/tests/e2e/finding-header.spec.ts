import { expect, test, type Locator, type Page } from '@playwright/test';
import type { FindingRecord } from '../../src/domain';

const title = 'An approval request retains an account identity across the fulfillment boundary and permits an order transition outside the initiating customer’s authorized scope';
const summary = ('A caller supplies an approval session that is accepted across the order and fulfillment boundaries without establishing the initiating account’s ownership. The reviewed trace records the preconditions and resulting authorization decision. ').repeat(7).trim();
const repository = 'storefront/' + 'approval-and-fulfillment-namespace-'.repeat(7) + 'service';
const execution = 'audit-20000101T000000Z-' + 'retained-assessed-execution-'.repeat(7) + 'complete';
const scope = 'assessment-' + 'original-source-scope-'.repeat(9) + 'reviewed';
const sourceView = 'derived-' + 'recorded-source-namespace-'.repeat(6) + 'view';

async function openLongFinding(page: Page) {
  await page.route('**/api/findings/*', async route => {
    const response = await route.fetch();
    const finding = await response.json() as FindingRecord;
    if (finding.id === 'F-001') {
      finding.title = finding.raw.title = title;
      finding.attackSummary = finding.raw.attack_summary = summary;
      finding.repositories = [repository];
      finding.runId = execution;
      finding.scopeId = scope;
      finding.sourceView = sourceView;
      if (finding.scope) {
        finding.scope.run_id = execution;
        finding.scope.assessment_id = scope;
        finding.scope.source_view = sourceView;
      }
    }
    await route.fulfill({ response, json: finding });
  });
  const finding = JSON.stringify(['finding', 'audit-fixture', 'F-001']);
  await page.goto('/?' + new URLSearchParams({ view: 'findings', finding, mode: 'procedure' }));
  await expect(page.locator('.finding-header')).toBeVisible();
}

async function noHorizontalOverflow(page: Page) {
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
}

async function expectUnclippedText(element: Locator) {
  await expect.poll(() => element.evaluate(node => node.scrollWidth <= node.clientWidth + 1 && node.scrollHeight <= node.clientHeight + 1)).toBe(true);
}

for (const viewport of [
  { label: 'desktop light', width: 1440, height: 1000, dark: false },
  { label: 'narrow dark', width: 390, height: 844, dark: true },
]) {
  test(`finding header preserves complete evidence context with readable hierarchy on ${viewport.label}`, async ({ page }) => {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.emulateMedia({ reducedMotion: 'reduce' });
    if (viewport.dark) await page.addInitScript(() => localStorage.setItem('stake-theme', 'dark'));
    await openLongFinding(page);
    if (viewport.dark) await expect(page.locator('html')).toHaveClass('dark');

    const header = page.locator('.finding-header');
    const main = header.locator('.finding-header-main');
    const heading = main.getByRole('heading', { level: 1 });
    await expect(heading).toHaveText(title);
    await expectUnclippedText(heading);
    await expect(main.locator('.detail-badges')).toContainText('F-001');
    await expect(main.locator('.detail-badges')).toContainText('confirmed');
    const facts = header.locator('dl.finding-header-facts');
    await expect(facts.locator('dt')).toHaveText(['Repository', 'Verification', 'Recorded steps', 'Proposed repairs']);
    const repositoryFact = facts.locator('div').filter({ has: page.getByText('Repository', { exact: true }) });
    await expect(repositoryFact.locator('dd')).toHaveText(repository);
    await expectUnclippedText(repositoryFact.locator('dd'));
    await expect(facts.locator('dd')).toContainText([repository, 'source verified', '2', '1']);
    await expect.poll(() => facts.locator('dd').evaluateAll(values => values.every(value => Number.parseFloat(getComputedStyle(value).fontSize) >= 11))).toBe(true);

    const context = header.getByRole('button', { name: /^Assessment context/ });
    await expect(context).toHaveAttribute('aria-expanded', 'false');
    await expect(header.getByText(execution, { exact: true })).not.toBeVisible();
    await expect(header.getByText(scope, { exact: true })).not.toBeVisible();
    await noHorizontalOverflow(page);
    await header.screenshot({ path: `/private/tmp/atstake-finding-header-${viewport.dark ? 'mobile' : 'desktop'}.png` });

    const paragraph = main.locator('.finding-summary-text');
    await expect(paragraph).toHaveText(summary);
    const expand = main.getByRole('button', { name: 'Read full summary', exact: true });
    await expect(expand).toBeVisible();
    await expect.poll(() => paragraph.evaluate(node => node.scrollHeight > node.clientHeight
      && node.clientHeight <= Number.parseFloat(getComputedStyle(node).lineHeight) * 3 + 2)).toBe(true);
    await expand.click();
    await expect(main.getByRole('button', { name: 'Show less', exact: true })).toBeVisible();
    await expectUnclippedText(paragraph);
    await expect(paragraph).toHaveText(summary);
    await noHorizontalOverflow(page);
    await main.getByRole('button', { name: 'Show less', exact: true }).click();
    await expect(expand).toBeVisible();

    await context.click();
    await expect(context).toHaveAttribute('aria-expanded', 'true');
    await expect(header.getByText(execution, { exact: true })).toBeVisible();
    await expect(header.getByText(scope, { exact: true })).toBeVisible();
    await expect(header.getByText(sourceView, { exact: true })).toBeVisible();
    await expectUnclippedText(header.getByText(execution, { exact: true }));
    await expectUnclippedText(header.getByText(scope, { exact: true }));
    await noHorizontalOverflow(page);

    const tabs = page.getByRole('tablist', { name: 'Finding detail', exact: true });
    await expect(tabs.getByRole('tab', { name: 'Summary', exact: true })).toHaveAttribute('data-state', 'active');
    await expect(page.getByRole('region', { name: 'Attack explorer', exact: true })).toHaveCount(0);
    await expect(header.locator('.graph-toolbar, .graph-repair-toolbar')).toHaveCount(0);
    await expect.poll(async () => {
      const headerBox = await header.boundingBox();
      const tabBox = await tabs.boundingBox();
      return Boolean(headerBox && tabBox && tabBox.y >= headerBox.y + headerBox.height - 1 && tabBox.y - headerBox.y - headerBox.height < 80);
    }).toBe(true);
    await tabs.getByRole('tab', { name: 'Attack map', exact: true }).click();
    const graphHeading = page.locator('.finding-graph-heading');
    await expect(graphHeading.getByRole('heading', { level: 2, name: 'Attack path', exact: true })).toBeVisible();
    await expect(page.getByRole('region', { name: 'Attack explorer', exact: true })).toBeVisible();
    await expect(page.getByRole('tab', { name: 'Attack procedure', exact: true })).toBeVisible();
  });
}
