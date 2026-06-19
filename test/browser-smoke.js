import assert from "node:assert/strict";
import path from "node:path";
import { chromium } from "playwright-core";

const executablePath = process.env.BROWSER_PATH || "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const baseUrl = process.env.TEST_BASE_URL || "http://127.0.0.1:3001";
const browser = await chromium.launch({ executablePath, headless: true });

try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  try {
    await page.goto(`${baseUrl}/login`);
    await page.getByLabel("Utilisateur").fill("admin");
    await page.getByLabel("Mot de passe").fill(process.env.TEST_ADMIN_PASSWORD || "admin");
    await page.getByRole("button", { name:"Connexion" }).click();
    await page.waitForURL(`${baseUrl}/`);
    const eventRequest = page.waitForRequest((request) => request.url().endsWith("/events"));
    await page.locator("[data-server]").first().click();
    await eventRequest;
    await page.locator("#installTitle").waitFor({ timeout:10000 });
    const lifecycle = await page.locator("#installTitle").textContent();
    if (!/opérationnel/i.test(lifecycle || "")) {
      assert.equal(await page.getByRole("button", { name:"Mondes" }).isVisible(), false);
      assert.equal(await page.getByRole("button", { name:"Console" }).isVisible(), false);
    }
    await page.locator("#performanceProfile").selectOption("performance");
    assert.equal(await page.locator("#resourceRam").inputValue(), "4096");
    assert.equal(await page.locator("#resourceCpu").inputValue(), "4");
    await page.locator("#performanceProfile").selectOption("balanced");
    await page.screenshot({ path:path.resolve(".panel", "browser-preflight.png"), fullPage:true });
    await page.getByRole("button", { name:"Comptes" }).click();
    await page.getByRole("heading", { name:"Comptes", exact:true }).waitFor();
    await page.locator("#userList .data-row").first().waitFor();
    await page.screenshot({ path:path.resolve(".panel", "browser-detail.png"), fullPage:true });
    await page.getByRole("button", { name:"Mes serveurs" }).click();
    await page.getByRole("button", { name:"Nouveau serveur" }).click();
    assert.equal(await page.locator("#createServerModal").evaluate((dialog) => dialog.open), true);
    await page.locator('[data-close-modal="createServerModal"]').first().click();
    assert.deepEqual(errors, []);
  } catch (error) {
    console.error(JSON.stringify({ url:page.url(), pageErrors:errors }));
    throw error;
  } finally {
    await page.screenshot({ path:path.resolve(".panel", "browser-smoke.png"), fullPage:true });
  }

  const mobile = await browser.newPage({ viewport: { width:390, height:844 } });
  await mobile.goto(`${baseUrl}/login`);
  await mobile.getByLabel("Utilisateur").fill("admin");
  await mobile.getByLabel("Mot de passe").fill(process.env.TEST_ADMIN_PASSWORD || "admin");
  await mobile.getByRole("button", { name:"Connexion" }).click();
  await mobile.waitForURL(`${baseUrl}/`);
  const overflow = await mobile.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  assert.ok(overflow <= 1, `Débordement horizontal mobile: ${overflow}px`);
  await mobile.screenshot({ path:path.resolve(".panel", "browser-smoke-mobile.png"), fullPage:true });
} finally {
  await browser.close();
}
