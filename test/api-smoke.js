import assert from "node:assert/strict";

const baseUrl = process.env.TEST_BASE_URL || "http://127.0.0.1:3001";
const login = await fetch(`${baseUrl}/login`, {
  method:"POST",
  redirect:"manual",
  headers:{ "content-type":"application/x-www-form-urlencoded" },
  body:new URLSearchParams({ username:"admin", password:process.env.TEST_ADMIN_PASSWORD || "admin" })
});
assert.equal(login.status, 302);
const cookie = login.headers.get("set-cookie")?.split(";")[0];
assert.ok(cookie);

const panel = await fetch(`${baseUrl}/`, { headers:{ cookie } });
const html = await panel.text();
const csrf = html.match(/name="_csrf" value="([^"]+)"/)?.[1];
assert.ok(csrf);

const name = `API smoke ${Date.now()}`;
const createdResponse = await request("/api/servers", {
  method:"POST",
  body:JSON.stringify({ name, port:23000 + Math.floor(Math.random() * 1000) })
});
assert.equal(createdResponse.status, 201);
const created = await createdResponse.json();

try {
  const statusResponse = await request(`/api/servers/${encodeURIComponent(created.server.id)}/status`);
  assert.equal(statusResponse.status, 200);
  const status = await statusResponse.json();
  assert.ok(["not-installed", "ready", "error"].includes(status.installationState));
} finally {
  const deleted = await request(`/api/servers/${encodeURIComponent(created.server.id)}`, {
    method:"DELETE",
    body:JSON.stringify({ confirm:name })
  });
  assert.equal(deleted.status, 200);
}

async function request(path, options = {}) {
  return fetch(`${baseUrl}${path}`, {
    ...options,
    headers:{ cookie, "content-type":"application/json", "x-csrf-token":csrf, ...(options.headers || {}) }
  });
}
