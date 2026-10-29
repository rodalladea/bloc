"use strict";
(() => {
  // Remove the fragment before any application script can submit a request.
  const fragment = new URLSearchParams(location.hash.slice(1));
  let code = fragment.get('code');
  if (location.hash) history.replaceState(null, '', location.pathname + location.search);
  const fill = () => { const field=document.querySelector('input[name="code"]'); if(field && code) field.value=code; code=null; };
  document.addEventListener('DOMContentLoaded',fill,{once:true});
  const finish=()=>{document.querySelectorAll('main button[data-original-label]').forEach(b=>{b.textContent=b.dataset.originalLabel;delete b.dataset.originalLabel;b.disabled=false;});document.querySelectorAll('.working,#realm-loading').forEach(e=>e.hidden=true);document.querySelector('main')?.removeAttribute('aria-busy');};
  document.addEventListener('htmx:beforeRequest',e=>{const main=document.querySelector('main');main?.setAttribute('aria-busy','true');if(e.detail.elt.closest('form')){main?.querySelectorAll('button[type="submit"]').forEach(b=>{b.dataset.originalLabel=b.textContent;b.textContent='Saving…';b.disabled=true;});const feedback=main?.querySelector('.working');if(feedback)feedback.hidden=false;}else{const loading=document.querySelector('#realm-loading');if(loading)loading.hidden=false;}});
  document.addEventListener('htmx:beforeSwap',e=>{if([400,403,404,409,413,415,422,429,503].includes(e.detail.xhr.status)){e.detail.shouldSwap=true;e.detail.isError=false;}});
  document.addEventListener('htmx:afterRequest',finish);
  document.addEventListener('htmx:afterSwap',()=>{finish();(document.querySelector('#feedback')||document.querySelector('#confirmation')||document.querySelector('main h1'))?.focus();});
  document.addEventListener('htmx:afterSettle',()=>{document.querySelectorAll('nav[aria-label="My Account"] a').forEach(a=>{if(location.pathname===a.pathname || location.pathname.startsWith(a.pathname+'/'))a.setAttribute('aria-current','page');else a.removeAttribute('aria-current');});});
  for(const event of ['htmx:sendError','htmx:timeout'])document.addEventListener(event,()=>{finish();const main=document.querySelector('main');if(!main)return;let alert=document.querySelector('#feedback');if(!alert){alert=document.createElement('div');alert.id='feedback';alert.className='notice ui-notice error ui-notice--error';alert.tabIndex=-1;alert.setAttribute('role','alert');main.querySelector('.heading')?.after(alert);}alert.replaceChildren(document.createTextNode('The response was lost. Your change may have been saved. Reload and review before trying again. '));const a=document.createElement('a');a.href=location.pathname;a.textContent='Reload';alert.append(a);alert.focus();});
  document.addEventListener('click',async e=>{const button=e.target.closest('[data-copy]');if(!button)return;const field=document.getElementById(button.dataset.copy);if(!field)return;try{await navigator.clipboard.writeText(field.value);button.textContent='Copied';}catch{field.select();button.textContent='Select and copy';}});
})();
