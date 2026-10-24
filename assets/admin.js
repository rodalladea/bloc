"use strict";
(() => {
 const initializeMenu = () => {
   const sidebar = document.querySelector('.sidebar');
   const toggle = sidebar?.querySelector('.mobile-menu-toggle');
   if (!toggle) return;
   const mobile = window.matchMedia('(max-width: 639px)');
   const drawer = sidebar.querySelector('.sidebar-content');
   const workspace = document.querySelector('.workspace');
   const header = sidebar.querySelector('.sidebar-header');
   const closeButton = sidebar.querySelector('.mobile-menu-close');
   const close = (restoreFocus = false) => {
     toggle.setAttribute('aria-expanded', 'false');
     sidebar.dataset.mobileMenu = 'ready';
     drawer.inert = mobile.matches;
     drawer.removeAttribute('role');
     drawer.removeAttribute('aria-modal');
     drawer.removeAttribute('aria-label');
     header.inert = false;
     if (workspace) workspace.inert = false;
     sidebar.querySelectorAll('[data-ui-dropdown][open]').forEach(menu => { menu.open = false; });
     if (restoreFocus) toggle.focus();
   };
   const open = () => {
     if (!mobile.matches) return;
     toggle.setAttribute('aria-expanded', 'true');
     sidebar.dataset.mobileMenu = 'open';
     drawer.inert = false;
     drawer.setAttribute('role', 'dialog');
     drawer.setAttribute('aria-modal', 'true');
     drawer.setAttribute('aria-label', 'Navigation');
     header.inert = true;
     if (workspace) workspace.inert = true;
     drawer.getBoundingClientRect();
     closeButton.focus();
   };
   toggle.hidden = false;
   sidebar.querySelector('.mobile-menu-backdrop').hidden = false;
   close();
   drawer.getBoundingClientRect();
   sidebar.dataset.menuMotion = 'ready';
   toggle.addEventListener('click', open);
   closeButton.addEventListener('click', () => close(true));
   sidebar.querySelector('.mobile-menu-backdrop').addEventListener('click', () => close(true));
   drawer.addEventListener('click', event => {
     if (mobile.matches && event.target.closest('a[href]')) close(true);
   });
   document.addEventListener('keydown', event => {
     if (!mobile.matches || sidebar.dataset.mobileMenu !== 'open') return;
     if (event.key === 'Escape') {
       event.preventDefault();
       close(true);
     } else if (event.key === 'Tab') {
       const controls = [...drawer.querySelectorAll('a[href], button, summary')].filter(control => control.getClientRects().length && !control.closest('[hidden]'));
       const first = controls[0];
       const last = controls[controls.length - 1];
       if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
       else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
     }
   });
   mobile.addEventListener('change', () => {
     const focusInside = drawer.contains(document.activeElement);
     close();
     if (mobile.matches && focusInside) toggle.focus();
   });
 };
 if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initializeMenu, { once: true });
 else initializeMenu();
 const clearSecrets = form => form.querySelectorAll('input[type="password"], input[name="code"]').forEach(input => { input.value = ""; });
 const finish = form => {if (!form) return; form.removeAttribute("aria-busy"); const button=form.querySelector('button[type="submit"]');if(button){button.disabled=false;if(button.dataset.label) button.textContent=button.dataset.label;}const status=form.querySelector('.working');if(status)status.hidden=true;};
 document.addEventListener("htmx:beforeRequest", event => {const form=event.detail.elt.closest('form');if(!form)return;form.setAttribute('aria-busy','true');const button=form.querySelector('button[type="submit"]');button.dataset.label=button.textContent;button.textContent='Working…';button.disabled=true;form.querySelector('.working').hidden=false;});
 document.addEventListener("htmx:beforeSwap", event => {if([400,401,409,422,429,503].includes(event.detail.xhr.status)){event.detail.shouldSwap=true;event.detail.isError=false;}});
 document.addEventListener("htmx:afterSwap", () => {const feedback=document.querySelector('#feedback');if(feedback)feedback.focus();});
 document.addEventListener("htmx:afterRequest", event=>finish(event.detail.elt.closest('form')));
 for(const name of ['htmx:sendError','htmx:timeout']) document.addEventListener(name,event=>{const form=event.detail.elt.closest('form');if(!form)return;clearSecrets(form);finish(form);let alert=document.querySelector('#feedback');if(!alert){alert=document.createElement('div');alert.id='feedback';alert.className='notice ui-notice error ui-notice--error';alert.tabIndex=-1;alert.setAttribute('role','alert');form.before(alert);}alert.textContent='The request could not be confirmed. Check your connection and try again.';alert.focus();});
})();
