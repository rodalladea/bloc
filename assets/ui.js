"use strict";
(() => {
  const pendingHeadings = new WeakMap();
  document.addEventListener("ui:pending", event => {
    const form = event.target.closest?.("[data-ui-pending-heading]");
    const heading = form?.closest("main")?.querySelector("h1");
    if (!heading) return;
    if (event.detail?.active) {
      if (!pendingHeadings.has(form)) pendingHeadings.set(form, { text: heading.textContent, title: document.title });
      heading.textContent = form.dataset.uiPendingHeading;
      document.title = "bloc — " + heading.textContent;
    } else {
      const previous = pendingHeadings.get(form);
      if (previous) { heading.textContent = previous.text; document.title = previous.title; pendingHeadings.delete(form); }
    }
  });
  const key = "bloc-ui.appearance";
  const root = document.documentElement;
  const valid = value => ["system", "light", "dark"].includes(value);
  const apply = value => {
    root.dataset.uiTheme = valid(value) ? value : "system";
    document.querySelectorAll("[data-ui-theme-control]").forEach(control => {
      control.value = root.dataset.uiTheme;
    });
    document.querySelectorAll("[data-ui-theme-choice]").forEach(button => {
      button.setAttribute("aria-pressed", String(button.dataset.uiThemeChoice === root.dataset.uiTheme));
    });
  };
  let saved;
  try { saved = localStorage.getItem(key); } catch { /* Storage is optional. */ }
  apply(root.hasAttribute("data-ui-theme-fixed") ? "system" : saved);
  const reveal = () => document.querySelectorAll("[data-ui-theme-picker]").forEach(picker => {
    picker.hidden = false;
    apply(root.dataset.uiTheme);
  });
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", reveal, { once: true });
  else reveal();
  document.addEventListener("change", event => {
    if (!(event.target instanceof Element) || !event.target.matches("[data-ui-theme-control]") || !event.target.closest(".ui") || !valid(event.target.value)) return;
    apply(event.target.value);
    try { localStorage.setItem(key, root.dataset.uiTheme); } catch { /* Keep the current choice without persistence. */ }
  });
  document.addEventListener("click", event => {
    if (!(event.target instanceof Element)) return;
    const button = event.target.closest(".ui [data-ui-theme-choice]");
    if (button && valid(button.dataset.uiThemeChoice)) {
      apply(button.dataset.uiThemeChoice);
      try { localStorage.setItem(key, root.dataset.uiTheme); } catch { /* Storage is optional. */ }
      const dropdown = button.closest("[data-ui-dropdown]");
      if (dropdown) { dropdown.open = false; dropdown.querySelector("summary").focus(); }
    }
    document.querySelectorAll(".ui [data-ui-dropdown][open]").forEach(menu => {
      if (!menu.contains(event.target)) menu.open = false;
    });
  });
  document.addEventListener("keydown", event => {
    if (event.key !== "Escape") return;
    document.querySelectorAll(".ui [data-ui-dropdown][open]").forEach(menu => {
      menu.open = false;
      menu.querySelector("summary").focus();
    });
  });
  window.addEventListener("storage", event => {
    if (!root.hasAttribute("data-ui-theme-fixed") && (event.key === key || event.key === null)) apply(event.newValue);
  });
})();

(() => {
  document.addEventListener("click", async event => {
    const button = event.target.closest?.("[data-ui-copy-codes], [data-ui-download-codes]");
    const handoff = button?.closest(".ui .ui-recovery-handoff");
    if (!handoff || button.disabled) return;
    const codes = handoff.querySelector("textarea[readonly]");
    const feedback = handoff.querySelector('[role="status"]');
    if (!codes || !feedback) return;
    try {
      if (button.hasAttribute("data-ui-copy-codes")) {
        await navigator.clipboard.writeText(codes.value);
        feedback.textContent = "Recovery codes copied.";
      } else {
        const url = URL.createObjectURL(new Blob([codes.value + "\n"], {type: "text/plain;charset=utf-8"}));
        const link = document.createElement("a");
        link.href = url;
        link.download = "bloc-recovery-codes.txt";
        link.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        feedback.textContent = "Recovery code download started. Check that you saved the file.";
      }
    } catch {
      feedback.textContent = "Select and save the codes manually, then confirm that you saved them.";
      codes.focus();
      codes.select();
    }
  });
})();
