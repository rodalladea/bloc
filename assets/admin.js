"use strict";
(() => {
 const clearSecrets = form => form.querySelectorAll('input[type="password"], input[name="code"]').forEach(input => { input.value = ""; });
 const finish = form => {if (!form) return; form.removeAttribute("aria-busy"); const button=form.querySelector('button[type="submit"]');if(button){button.disabled=false;if(button.dataset.label) button.textContent=button.dataset.label;}const status=form.querySelector('.working');if(status)status.hidden=true;};
 document.addEventListener("htmx:beforeRequest", event => {const form=event.detail.elt.closest('form');if(!form)return;form.setAttribute('aria-busy','true');const button=form.querySelector('button[type="submit"]');button.dataset.label=button.textContent;button.textContent='Working…';button.disabled=true;form.querySelector('.working').hidden=false;});
 document.addEventListener("htmx:beforeSwap", event => {if([400,401,409,422,429,503].includes(event.detail.xhr.status)){event.detail.shouldSwap=true;event.detail.isError=false;}});
 document.addEventListener("htmx:afterSwap", () => {const feedback=document.querySelector('#feedback');if(feedback)feedback.focus();});
 document.addEventListener("htmx:afterRequest", event=>finish(event.detail.elt.closest('form')));
 for(const name of ['htmx:sendError','htmx:timeout']) document.addEventListener(name,event=>{const form=event.detail.elt.closest('form');if(!form)return;clearSecrets(form);finish(form);let alert=document.querySelector('#feedback');if(!alert){alert=document.createElement('div');alert.id='feedback';alert.className='notice ui-notice error ui-notice--error';alert.tabIndex=-1;alert.setAttribute('role','alert');form.before(alert);}alert.textContent='The request could not be confirmed. Check your connection and try again.';alert.focus();});
})();
