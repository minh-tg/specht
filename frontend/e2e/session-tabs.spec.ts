import { expect, test } from "@playwright/test";
import { uiLogin } from "./helpers";

interface StoredSession {
  accessToken: string;
  refreshToken: string;
}

for (const mode of ["worker", "locks"]) {
  test(`duplicated tabs share successive refreshes without revoking their family (${mode})`, async ({ page, context, request }) => {
    if (mode === "locks") {
      await context.addInitScript(() => {
        Object.defineProperty(window, "SharedWorker", { value: undefined, configurable: true });
      });
    }
    await uiLogin(page);
    const original = await page.evaluate(() =>
      JSON.parse(sessionStorage.getItem("specht.session")!) as StoredSession
    );

    // Expire the access response once per document. The worker still calls the
    // real single-use refresh endpoint, so an uncoordinated copy revokes it.
    await context.addInitScript(() => {
      const originalFetch = window.fetch.bind(window);
      let expired = false;
      window.fetch = (input, init) => {
        if (!expired && String(input).startsWith("/api/v1/projects")) {
          expired = true;
          return Promise.resolve(
            new Response(JSON.stringify({ error: { code: "unauthorized", message: "expired" } }), {
              status: 401,
              headers: { "Content-Type": "application/json" },
            }),
          );
        }
        return originalFetch(input, init);
      };
    });
    const opened = page.waitForEvent("popup");
    await page.evaluate(() => {
      window.open("/", "_blank");
    });
    const copy = await opened;
    await page.reload();

    for (const tab of [page, copy]) {
      await expect(tab.getByRole("heading", { name: "Projects", exact: true })).toBeVisible();
      await expect.poll(async () => tab.evaluate(() => sessionStorage.getItem("specht.session")))
        .not
        .toBeNull();
    }
    await expect.poll(async () =>
      page.evaluate(
        (previous) =>
          (JSON.parse(sessionStorage.getItem("specht.session")!) as StoredSession).refreshToken
            !== previous,
        original.refreshToken,
      )
    ).toBe(true);
    const first = await page.evaluate(() =>
      JSON.parse(sessionStorage.getItem("specht.session")!) as StoredSession
    );
    await expect.poll(async () =>
      copy.evaluate(
        (expected) =>
          (JSON.parse(sessionStorage.getItem("specht.session")!) as StoredSession).refreshToken
            === expected,
        first.refreshToken,
      )
    ).toBe(true);
    const second = await copy.evaluate(() =>
      JSON.parse(sessionStorage.getItem("specht.session")!) as StoredSession
    );
    expect(first.refreshToken !== original.refreshToken).toBe(true);
    expect(second.refreshToken === first.refreshToken).toBe(true);

    await Promise.all([page.reload(), copy.reload()]);
    for (const tab of [page, copy]) {
      await expect(tab.getByRole("heading", { name: "Projects", exact: true })).toBeVisible();
    }
    await expect.poll(async () =>
      page.evaluate(
        (previous) =>
          (JSON.parse(sessionStorage.getItem("specht.session")!) as StoredSession).refreshToken
            !== previous,
        first.refreshToken,
      )
    ).toBe(true);
    const next = await page.evaluate(() =>
      JSON.parse(sessionStorage.getItem("specht.session")!) as StoredSession
    );
    expect(next.refreshToken !== first.refreshToken).toBe(true);
    await expect.poll(async () =>
      copy.evaluate(
        (expected) =>
          (JSON.parse(sessionStorage.getItem("specht.session")!) as StoredSession).refreshToken
            === expected,
        next.refreshToken,
      )
    ).toBe(true);
    const live = await request.get("/api/v1/me", {
      headers: { Authorization: `Bearer ${next.accessToken}` },
    });
    expect(live.ok()).toBeTruthy();

    // A caller outside the same-origin worker still triggers server replay
    // rejection and revokes the successor. No grace window was added.
    const replay = await request.post("/api/v1/auth/refresh", {
      data: { refresh_token: original.refreshToken },
    });
    expect(replay.status()).toBe(401);
    const successor = await request.post("/api/v1/auth/refresh", {
      data: { refresh_token: next.refreshToken },
    });
    expect(successor.status()).toBe(401);
  });
}

test("a missing refresh peer never causes a spent token to be resubmitted", async ({ page, context, request }) => {
  await context.addInitScript(() => {
    Object.defineProperty(window, "SharedWorker", { value: undefined, configurable: true });
  });
  await uiLogin(page);
  const original = await page.evaluate(() =>
    JSON.parse(sessionStorage.getItem("specht.session")!) as StoredSession
  );
  await page.evaluate(async (token) => {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
    const key = "specht.refresh.used."
      + Array.from(new Uint8Array(digest), (v) => v.toString(16).padStart(2, "0")).join("");
    localStorage.setItem(key, String(Date.now() + 60_000));
  }, original.refreshToken);
  await context.addInitScript(() => {
    const originalFetch = window.fetch.bind(window);
    let expired = false;
    window.fetch = (input, init) => {
      if (!expired && String(input).startsWith("/api/v1/projects")) {
        expired = true;
        return Promise.resolve(new Response("{}", { status: 401 }));
      }
      return originalFetch(input, init);
    };
  });
  let refreshes = 0;
  context.on("request", (r) => {
    if (r.url().endsWith("/api/v1/auth/refresh")) refreshes++;
  });
  await page.reload();
  // The fallback waits 150 ms for a peer before refusing to replay.
  await page.waitForTimeout(500);
  expect(refreshes).toBe(0);
  const storage = await page.evaluate(() => JSON.stringify(localStorage));
  expect(storage.includes(original.refreshToken)).toBe(false);
  const stillUnused = await request.post("/api/v1/auth/refresh", {
    data: { refresh_token: original.refreshToken },
  });
  expect(stillUnused.status()).toBe(200);
});
