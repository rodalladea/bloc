"use strict";
(() => {
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
  apply(saved);
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
    if (event.key === key || event.key === null) apply(event.newValue);
  });
})();
