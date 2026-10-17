import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const output = resolve(process.argv[2] || "evidence/administrator-preview");
await mkdir(output, { recursive: true });
const target = await (await fetch("http://127.0.0.1:9223/json/new?about:blank", { method: "PUT" })).json();
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((done, fail) => { ws.addEventListener("open", done, { once: true }); ws.addEventListener("error", fail, { once: true }); });
let id = 0;
const pending = new Map();
const errors = [];
const requests = [];
ws.addEventListener("message", event => {
  const message = JSON.parse(event.data);
  if (message.method === "Runtime.exceptionThrown") errors.push(message.params.exceptionDetails);
  if (message.method === "Network.requestWillBeSent") requests.push(message.params.request);
  if (message.id && pending.has(message.id)) {
    const { done, fail, timer } = pending.get(message.id);
    clearTimeout(timer); pending.delete(message.id);
    if (message.error) fail(new Error(JSON.stringify(message.error))); else done(message.result);
  }
});
function send(method, params = {}) {
  return new Promise((done, fail) => {
    const requestId = ++id;
    const timer = setTimeout(() => { pending.delete(requestId); fail(new Error(`Timed out: ${method}`)); }, 10000);
    pending.set(requestId, { done, fail, timer });
    ws.send(JSON.stringify({ id: requestId, method, params }));
  });
}
async function evaluate(expression) {
  const response = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
  assert(!response.exceptionDetails, JSON.stringify(response.exceptionDetails));
  return response.result.value;
}
try {
  await send("Page.enable"); await send("Runtime.enable"); await send("Network.enable");
  await send("Page.navigate", { url: pathToFileURL(resolve("prototypes/administrator-access/index.html")).href });
  for (let attempt = 0; attempt < 50; attempt++) {
    if (await evaluate('!!document.querySelector("main h1")')) break;
    await new Promise(done => setTimeout(done, 100));
  }
  const results = [];
  for (const width of [375, 1280]) {
    await send("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: false });
    for (const screen of ["setup", "login", "recovery", "password", "home"]) {
      await evaluate(`selectScreen(${JSON.stringify(screen)})`);
      const available = await evaluate('Array.from(document.querySelector("#state").options, option => option.value)');
      for (const state of available) {
        await evaluate(`document.querySelector("#state").value=${JSON.stringify(state)}; render(true)`);
        const result = await evaluate(`(() => {
          const inputs = [...document.querySelectorAll("main input")];
          return {
            heading: document.querySelector("main h1").textContent,
            width: innerWidth, scrollWidth: document.documentElement.scrollWidth,
            labels: inputs.every(input => document.querySelector('label[for="' + input.id + '"]')),
            emptySecrets: inputs.filter(input => input.type === "password" || input.name === "code").every(input => input.value === ""),
            focus: document.activeElement.id,
            hasProtectedContent: !!document.querySelector("dl"),
            invalidFields: document.querySelectorAll('[aria-invalid="true"]').length,
            busy: !!document.querySelector('[aria-busy="true"]'),
            disabled: !!document.querySelector("main button:disabled")
          };
        })()`);
        assert(result.scrollWidth <= width, `Overflow: ${screen}/${state}/${width}`);
        assert(result.labels && result.emptySecrets, `Field contract: ${screen}/${state}`);
        assert(["content", "feedback"].includes(result.focus), `Focus: ${screen}/${state}`);
        if (state === "expired") {
          assert.equal(result.heading, "Sign in to bloc"); assert(!result.hasProtectedContent);
        }
        if (state === "validation") assert(result.invalidFields > 0);
        if (state === "loading") assert(result.busy && result.disabled);
        if (screen === "home" && state === "default") assert(result.hasProtectedContent);
        const screenshot = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: true });
        await writeFile(resolve(output, `${screen}-${state}-${width}.png`), Buffer.from(screenshot.data, "base64"));
        results.push({ screen, state, ...result });
      }
    }
  }
  await evaluate('selectScreen("login"); document.querySelector("#email").value="operator@example.test"; document.querySelector("#password").value="synthetic preview fixture"; document.querySelector("form").requestSubmit()');
  assert(await evaluate('document.querySelector("#password").value === "" && !!document.querySelector("#preview-result")'));
  assert.equal(requests.filter(request => request.method === "POST").length, 0);
  assert.equal(requests.filter(request => /^https?:/.test(request.url)).length, 0);
  await evaluate('selectScreen("setup"); document.querySelector("#code").focus()');
  await send("Input.dispatchKeyEvent", { type: "keyDown", key: "Tab", code: "Tab", windowsVirtualKeyCode: 9 });
  await send("Input.dispatchKeyEvent", { type: "keyUp", key: "Tab", code: "Tab", windowsVirtualKeyCode: 9 });
  assert.equal(await evaluate("document.activeElement.id"), "email");
  assert.equal(await evaluate('getComputedStyle(document.querySelector("#email")).outlineStyle'), "solid");
  const boundaryContrast = await evaluate(`(() => {
    function luminance(color) {
      const rgb = color.match(/[0-9.]+/g).slice(0, 3).map(Number).map(value => {
        value /= 255; return value <= .04045 ? value / 12.92 : ((value + .055) / 1.055) ** 2.4;
      });
      return rgb[0] * .2126 + rgb[1] * .7152 + rgb[2] * .0722;
    }
    const style = getComputedStyle(document.querySelector("#email"));
    const border = luminance(style.borderTopColor), background = luminance(style.backgroundColor);
    return (Math.max(border, background) + .05) / (Math.min(border, background) + .05);
  })()`);
  assert(boundaryContrast >= 3, "Input boundary needs at least 3:1 contrast");
  assert.equal(errors.length, 0, JSON.stringify(errors));
  const report = { browser: await (await fetch("http://127.0.0.1:9223/json/version")).json(), checks: results.length, results, postRequests: 0, externalRequests: 0, keyboardTab: "code → email; visible outline", inputBoundaryContrast: boundaryContrast, limitations: ["Design viewer only; no HTTP status, HTMX, authorization or screen-reader announcement proof", "Application no-JavaScript fallback is not implemented by this viewer"] };
  await writeFile(resolve(output, "browser-checks.json"), JSON.stringify(report, null, 2) + "\n");
  console.log(JSON.stringify({ checks: results.length, screenshots: results.length, output, errors: errors.length }));
} finally {
  await send("Page.close");
  ws.close();
}
