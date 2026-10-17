"use strict";
const screens = {
  setup: { title: "Set up bloc", intro: "Create the installation administrator using a code generated through deployment access.", action: "Create administrator", fields: ["code", "email", "password", "confirmation"] },
  login: { title: "Sign in to bloc", intro: "Use your installation administrator account.", action: "Sign in", fields: ["email", "password"] },
  recovery: { title: "Recover administrator access", intro: "Generate a recovery code through deployment access, then choose a new password.", action: "Reset password", fields: ["code", "password", "confirmation"] },
  password: { title: "Change password", intro: "Enter your current password and choose a replacement.", action: "Change password", fields: ["current", "password", "confirmation"] },
  home: { title: "Administration", intro: "Your installation and administrator account." },
};
const states = {
  setup: ["default", "closed", "unusable", "validation", "loading", "unavailable", "network"],
  login: ["default", "credentials", "validation", "loading", "expired", "unavailable", "network", "limited"],
  recovery: ["default", "unusable", "validation", "loading", "unavailable", "network"],
  password: ["default", "current-password", "validation", "loading", "expired", "unavailable", "network"],
  home: ["default", "loading", "expired", "unavailable", "network"],
};
const stateLabels = { default: "Default", closed: "Setup closed", unusable: "Invalid / expired code", validation: "Field validation", loading: "Working", unavailable: "Storage unavailable", network: "Network failure", expired: "Session expired", credentials: "Wrong credentials", "current-password": "Wrong current password", limited: "Rate limited" };
const labels = { code: "Operator code", email: "Email address", current: "Current password", password: "Password", confirmation: "Confirm password" };
const screenControl = document.querySelector("#screen");
const stateControl = document.querySelector("#state");
const content = document.querySelector("#content");

function field(key, screen, state) {
  const label = key === "password" && screen !== "login" && screen !== "setup" ? "New password" : labels[key];
  const invalid = state === "validation" && (screen === "login" ? key === "email" : key === "password");
  const type = key === "email" ? "email" : key === "code" ? "text" : "password";
  const help = key === "password" && screen !== "login" ? '<p class="help" id="password-help">Use 15–128 characters. Spaces and paste are allowed.</p>' : "";
  const error = invalid ? `<p class="field-error" id="${key}-error">${key === "email" ? "Enter an email address." : "Choose a password with 15–128 characters."}</p>` : "";
  const described = [help ? "password-help" : "", invalid ? `${key}-error` : ""].filter(Boolean).join(" ");
  return `<div class="field"><label for="${key}">${label}</label><input id="${key}" name="${key}" type="${type}" autocomplete="off"${key === "code" ? ' spellcheck="false" autocapitalize="none"' : ""}${invalid ? ' aria-invalid="true"' : ""}${described ? ` aria-describedby="${described}"` : ""}>${help}${error}</div>`;
}
function alertBox(message, error = true) {
  return `<div class="notice ${error ? "error" : ""}" id="feedback" tabindex="-1" role="${error ? "alert" : "status"}">${message}</div>`;
}
function render(focus = false) {
  let screen = screenControl.value;
  const state = stateControl.value;
  if (state === "expired") screen = "login";
  const spec = screens[screen];
  document.title = `bloc — ${spec.title} preview`;
  content.className = screen === "home" ? "home" : "";
  let feedback = "";
  if (state === "expired") feedback = alertBox("Your session ended. Sign in again.", false);
  if (state === "unusable") feedback = alertBox("This code cannot be used. Generate a new code and try again.");
  if (state === "credentials") feedback = alertBox("Email or password is incorrect.");
  if (state === "current-password") feedback = alertBox("Password change was refused. Check your current password.");
  if (state === "network") feedback = alertBox("The request could not be confirmed. Check your connection and try again.");
  if (state === "limited") feedback = alertBox("Too many attempts. Wait 60 seconds, then try again.");
  if (state === "validation") feedback = alertBox(`Check the highlighted field. <a href="#${screen === "login" ? "email" : "password"}">${screen === "login" ? "Enter your email address" : "Check your password"}</a>.`);
  if (state === "closed") {
    content.innerHTML = '<p class="eyebrow">Installation access</p><h1>Setup is complete</h1><p>This installation already has an administrator.</p><div class="actions"><a class="button" href="#login">Sign in</a><a class="text-link" href="#recovery">Recover access</a></div>';
  } else if (state === "unavailable") {
    content.innerHTML = '<h1>Temporarily unavailable</h1>' + alertBox('bloc cannot access the information needed for this request. Try again shortly.') + '<a class="button" href="#' + screen + '">Try again</a>';
  } else if (screen === "home") {
    content.innerHTML = `<h1>${spec.title}</h1><p class="intro">${spec.intro}</p>${feedback}<div class="grid"><section class="panel"><h2>Account</h2><dl><dt>Email address</dt><dd>operator@example.test</dd><dt>Role</dt><dd>Installation administrator</dd><dt>Email status</dt><dd>Unverified sign-in identifier</dd></dl></section><section class="panel"><h2>Installation</h2><dl><dt>Setup</dt><dd><span class="badge">Setup complete</span></dd><dt>bloc version</dt><dd>0.0.1 <span class="help">(preview fixture)</span></dd></dl></section></div><div class="actions"><a class="button" href="#password">Change password</a><form method="dialog"><button class="secondary"${state === "loading" ? ' disabled aria-busy="true"' : ""}>${state === "loading" ? "Working…" : "Sign out"}</button></form></div>${state === "loading" ? '<p role="status">Working…</p>' : ""}`;
  } else {
    const command = screen === "setup" ? "bloc admin setup-code" : screen === "recovery" ? "bloc admin recovery-code" : "";
    const note = screen === "password" || screen === "recovery" ? '<p class="notice">Completing this change ends all active sessions. You will need to sign in again.</p>' : "";
    const secondary = screen === "login" ? '<a class="text-link" href="#recovery">Recover access</a>' : `<a class="text-link" href="#${screen === "password" ? "home" : "login"}">${screen === "password" ? "Back to administration" : "Back to sign in"}</a>`;
    content.innerHTML = `<p class="eyebrow">Installation access</p><h1>${spec.title}</h1><p class="intro">${spec.intro}</p><section class="panel" aria-label="${spec.title}">${command ? `<p class="notice">With deployment access, run <code>${command}</code>. Codes expire after 15 minutes.</p>` : ""}${feedback}<form method="dialog"${state === "loading" ? ' aria-busy="true"' : ""}>${spec.fields.map(key => field(key, screen, state)).join("")}${note}<div class="actions"><button type="submit"${state === "loading" ? " disabled" : ""}>${state === "loading" ? "Working…" : spec.action}</button>${secondary}</div>${state === "loading" ? '<p class="help" role="status">Working…</p>' : ""}</form></section>${screen === "setup" ? '<p class="below-form">The email address is a sign-in identifier. No verification email will be sent.</p>' : ""}`;
  }
  content.querySelectorAll("form").forEach(form => form.addEventListener("submit", event => {
    event.preventDefault();
    form.querySelectorAll("input").forEach(input => { input.value = ""; });
    const existing = content.querySelector("#preview-result");
    if (existing) existing.remove();
    const result = document.createElement("p");
    result.id = "preview-result";
    result.className = "notice";
    result.setAttribute("role", "status");
    result.textContent = "Design preview only. Nothing was submitted or saved.";
    form.prepend(result);
  }));
  if (focus) (content.querySelector("#feedback") || content).focus();
}
function selectScreen(screen, state = "default", focus = false) {
  screenControl.value = Object.hasOwn(screens, screen) ? screen : "login";
  stateControl.replaceChildren(...states[screenControl.value].map(value => {
    const option = document.createElement("option"); option.value = value; option.textContent = stateLabels[value]; return option;
  }));
  stateControl.value = states[screenControl.value].includes(state) ? state : "default";
  render(focus);
}
screenControl.addEventListener("change", () => selectScreen(screenControl.value, "default", true));
stateControl.addEventListener("change", () => render(true));
window.addEventListener("hashchange", () => selectScreen(location.hash.slice(1), "default", true));
selectScreen(location.hash.slice(1) || "login");
