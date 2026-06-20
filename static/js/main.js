// ── Toast notifications ──────────────────────────────────────────────────────
function showToast(msg, type = 'success') {
  const t = document.getElementById('toast');
  if (!t) return;
  t.textContent = msg;
  t.className = (type === 'error' ? 'error ' : '') + 'show';
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.classList.remove('show'), 4500);
}

// ── Flag submission ──────────────────────────────────────────────────────────
function submitFlag(challengeId) {
  const input = document.getElementById('flag-input');
  if (!input) return;
  const flag = input.value.trim();
  if (!flag) { showToast('Enter a flag first.', 'error'); return; }

  const btn = document.getElementById('flag-btn');
  if (btn) btn.disabled = true;

  fetch('/submit_flag', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `flag=${encodeURIComponent(flag)}&challenge_id=${encodeURIComponent(challengeId)}`
  })
  .then(r => r.json())
  .then(data => {
    showToast(data.message, data.success ? 'success' : 'error');
    if (data.success && !data.already_solved) {
      const card = document.querySelector('.ch-header');
      if (card) {
        const badge = document.createElement('span');
        badge.className = 'badge badge-easy';
        badge.textContent = '✓ SOLVED';
        badge.style.marginLeft = '10px';
        card.querySelector('h2').appendChild(badge);
      }
      input.value = '';
    }
  })
  .catch(() => showToast('Network error.', 'error'))
  .finally(() => { if (btn) btn.disabled = false; });
}

// ── Hint toggle ──────────────────────────────────────────────────────────────
function toggleHint(id) {
  const el = document.getElementById(id);
  if (el) el.classList.toggle('show');
}

// ── Bot simulator for stored XSS ─────────────────────────────────────────────
function runBot() {
  const out = document.getElementById('bot-output');
  if (out) { out.textContent = '[ Bot is visiting the comments page… ]'; out.style.color = '#888'; }
  fetch('/challenges/xss_stored/bot')
    .then(r => r.json())
    .then(data => {
      if (out) {
        out.style.color = data.xss_triggered ? 'var(--green)' : 'var(--red)';
        out.textContent = data.message;
      }
    })
    .catch(() => { if (out) out.textContent = 'Error contacting bot.'; });
}

// ── CSRF simulate ────────────────────────────────────────────────────────────
function simulateCsrf() {
  const email = document.getElementById('csrf-email-input');
  if (!email || !email.value.trim()) { showToast('Enter a target email.', 'error'); return; }

  const form = document.createElement('form');
  form.method = 'POST';
  form.action = '/challenges/csrf/change_email';
  const inp = document.createElement('input');
  inp.type = 'hidden'; inp.name = 'email'; inp.value = email.value.trim();
  form.appendChild(inp);
  document.body.appendChild(form);
  form.submit();
}

// ── Typing animation ─────────────────────────────────────────────────────────
function typeText(el, text, speed) {
  let i = 0; el.textContent = '';
  const t = setInterval(() => {
    el.textContent += text[i++];
    if (i >= text.length) clearInterval(t);
  }, speed);
}

// ── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const typer = document.querySelector('[data-type]');
  if (typer) typeText(typer, typer.getAttribute('data-type'), 38);

  // Allow Enter key on flag input
  const fi = document.getElementById('flag-input');
  if (fi) {
    fi.addEventListener('keydown', e => {
      if (e.key === 'Enter') {
        const cid = fi.closest('[data-challenge]')?.getAttribute('data-challenge');
        if (cid) submitFlag(cid);
      }
    });
  }
});
