// Regression guard for a stored-XSS fix in the live-served operator/owner pages.
//
// dashboard.html interpolates attacker-controlled values (an agent's bio, a
// reporter's comment) into title="..." attributes. The old esc() did a
// textContent round-trip, which escapes <>& but NOT quotes — so a bio like
//   x" onmouseover="steal()
// broke out of the attribute and injected a handler in the admin origin (where
// the operator has typed the admin token). esc() must encode quotes too. This
// asserts the shipped esc() in each page is attribute-safe by evaluating it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

// Pull the esc() definition out of the page and materialize it. The shipped
// version is pure string ops (no DOM), so it runs as-is under node.
function loadEsc(file) {
  const src = fs.readFileSync(path.join(here, '..', 'site', file), 'utf8');
  const start = src.indexOf('function esc(s)');
  assert.ok(start >= 0, `esc() not found in ${file}`);
  // Balance braces from the function's opening { to its close.
  const open = src.indexOf('{', start);
  let depth = 0, end = -1;
  for (let i = open; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}') { depth--; if (depth === 0) { end = i + 1; break; } }
  }
  assert.ok(end > 0, `could not bound esc() in ${file}`);
  const fnSrc = src.slice(start, end);
  // eslint-disable-next-line no-new-func
  return new Function(`${fnSrc}\nreturn esc;`)();
}

for (const file of ['dashboard.html', 'owner.html']) {
  test(`${file}: esc() is attribute-safe (encodes quotes) — the XSS fix holds`, () => {
    const esc = loadEsc(file);
    // The attribute-breakout payload must not survive as a raw double-quote.
    assert.ok(!esc('x" onmouseover="steal()').includes('"'), 'double-quote must be encoded');
    // All HTML-significant characters encode.
    assert.equal(esc('a"b\'c<d>e&f`g'), 'a&quot;b&#39;c&lt;d&gt;e&amp;f&#96;g');
    // Plain text is untouched; nullish is empty.
    assert.equal(esc('hello world'), 'hello world');
    assert.equal(esc(null), '');
  });
}
