# Administrator access design preview

Open `index.html` in a browser. Use the screen and state controls to inspect setup,
sign-in, recovery, password change and administration home. The viewer runs only
locally, uses synthetic values, makes no submissions and saves nothing. It is
not part of bloc's router or evidence that authentication works.

The preview and its error-state copy were adopted by the requester on
2026-10-17. The canonical design and approval record live in Catapio Drive at
`projects/bloc/design/administrator-access-prerequisites.md`
(file ID `e8e306130bdbf3a9b158f1fe1c757a6baed52ae8f212b4fa`).

Browser checks use an isolated headless Chrome profile with remote debugging
on loopback port 9223. With Chrome running, execute from the repository root:

```sh
node prototypes/administrator-access/check.mjs
```

Screenshots and a JSON report go to ignored `evidence/administrator-preview/`.
The checker covers every available state at 375px and 1280px: horizontal overflow,
labels, empty secret fields, error focus, expiry navigation, busy controls, no
POST/external requests, and a real keyboard Tab transition with visible focus.
It does not verify a screen reader, HTMX, HTTP status codes, actual permissions,
or no-JavaScript application fallback. The viewer needs JavaScript to change
screens; the planned application must work through normal links and forms.
