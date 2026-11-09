(() => {
  "use strict";
  const decode = (value) => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
  const encode = (value) => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  function options(value, registration) {
    const key = value.publicKey;
    key.challenge = decode(key.challenge);
    if (registration) {
      key.user.id = decode(key.user.id);
      key.excludeCredentials = (key.excludeCredentials || []).map(c => ({ ...c, id: decode(c.id) }));
    } else {
      key.allowCredentials = (key.allowCredentials || []).map(c => ({ ...c, id: decode(c.id) }));
    }
    return key;
  }
  function serialize(credential, registration) {
    const response = credential.response;
    const value = { id: credential.id, rawId: encode(credential.rawId), type: credential.type, extensions: credential.getClientExtensionResults(), response: { clientDataJSON: encode(response.clientDataJSON) } };
    if (registration) {
      value.response.attestationObject = encode(response.attestationObject);
      if (response.getTransports) value.response.transports = response.getTransports();
    } else {
      value.response.authenticatorData = encode(response.authenticatorData);
      value.response.signature = encode(response.signature);
      value.response.userHandle = response.userHandle ? encode(response.userHandle) : null;
    }
    return value;
  }
  function initialize() {
    document.querySelectorAll("[data-webauthn-form]").forEach(form => {
      if (form.dataset.webauthnReady) return;
      form.dataset.webauthnReady = "true";
      const button = form.querySelector("[data-webauthn-submit]");
      const status = document.querySelector("#content [data-webauthn-status]");
      const fallback = document.querySelector("#content [data-webauthn-fallback]");
      const intro = document.querySelector("#content [data-webauthn-intro]");
      fallback.textContent = "Choose another method";
      const actionLabel = button.textContent;
      const registration = form.dataset.webauthnKind === "register";
      if (!window.PublicKeyCredential || !navigator.credentials || !window.isSecureContext) {
        const heading = document.querySelector("#content h1");
        if (heading) heading.textContent = "Passkey unavailable";
        if (intro) intro.hidden = true;
        document.title = "bloc — Passkey unavailable";
        status.textContent = "This browser or authenticator can’t complete the request. Use another enrolled method or an enabled recovery path.";
        status.hidden = false;
        return;
      }
      const heading = document.querySelector("#content [data-webauthn-heading]");
      if (heading) { heading.textContent = heading.dataset.webauthnHeading; document.title = "bloc — " + heading.textContent; }
      if (intro) intro.textContent = intro.dataset.webauthnIntro;
      status.hidden = registration;
      form.hidden = false;
      button.hidden = false;
      form.addEventListener("submit", async event => {
        event.preventDefault();
        if (button.disabled || !form.reportValidity()) return;
        button.disabled = true;
        button.setAttribute("aria-busy", "true");
        button.textContent = "Checking…";
        status.classList.add("ui-sr-only");
        status.hidden = false;
        form.setAttribute("aria-busy", "true");
        form.dispatchEvent(new CustomEvent("ui:pending", { bubbles: true, detail: { active: true } }));
        status.textContent = "Please wait while verification completes. A repeated submission does not extend this flow.";
        let retryMessage;
        try {
          const body = new URLSearchParams({ csrf: form.elements.csrf.value });
          if (registration) body.set("label", form.elements.label.value);
          const response = await fetch(form.dataset.webauthnOptions, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body, redirect: "error", cache: "no-store" });
          if (response.status === 429) {
            const seconds = Number(response.headers.get("Retry-After"));
            retryMessage = Number.isSafeInteger(seconds) && seconds > 0
              ? `Too many attempts. Try again in ${seconds} ${seconds === 1 ? "second" : "seconds"} or choose another method.`
              : "Too many attempts. Wait before trying again or choose another method.";
          }
          if (!response.ok) throw new Error("server");
          const publicOptions = await response.json();
          const publicKey = options(publicOptions, registration);
          const credential = registration ? await navigator.credentials.create({ publicKey }) : await navigator.credentials.get({ publicKey });
          if (!credential) throw new DOMException("Canceled", "NotAllowedError");
          // A native navigation preserves one-time recovery handoff delivery after303.
          const finish = document.createElement("form");
          finish.method = "post";
          finish.action = form.action;
          finish.setAttribute("hx-boost", "false");
          for (const [name, value] of Object.entries({ csrf: form.elements.csrf.value, ceremony_id: publicOptions.ceremony_id, credential: JSON.stringify(serialize(credential, registration)) })) {
            const field = document.createElement("input"); field.type = "hidden"; field.name = name; field.value = value; finish.appendChild(field);
          }
          document.body.appendChild(finish);
          HTMLFormElement.prototype.submit.call(finish);
        } catch (error) {
          status.textContent = retryMessage ?? (error.name === "NotAllowedError" || error.name === "AbortError"
            ? "Canceled the prompt? Try again or choose another method. Your factors have not changed."
            : "This browser or authenticator can’t complete the request. Try again, use another enrolled method or an enabled recovery path.");
          button.disabled = false;
          button.removeAttribute("aria-busy");
          button.textContent = actionLabel;
          status.classList.remove("ui-sr-only");
          form.removeAttribute("aria-busy");
          form.dispatchEvent(new CustomEvent("ui:pending", { bubbles: true, detail: { active: false } }));
          button.focus();
        }
      });
    });
  }
  document.addEventListener("DOMContentLoaded", initialize);
  document.addEventListener("htmx:load", initialize);
  initialize();
})();
