// ── Side chat panel (Grok) ───────────────────────────────────────────────────
(function () {
  const toggle  = document.getElementById('chat-toggle');
  const panel   = document.getElementById('chat-panel');
  const closeBtn= document.getElementById('chat-close');
  const form    = document.getElementById('chat-form');
  const input   = document.getElementById('chat-input');
  const sendBtn = document.getElementById('chat-send');
  const log         = document.getElementById('chat-messages');
  const modelSelect = document.getElementById('chat-model-select');
  const modeBtn     = document.getElementById('chat-mode-btn');
  if (!toggle || !panel || !form) return;

  let chatMode = 'chat';
  if (modeBtn) {
    modeBtn.addEventListener('click', () => {
      chatMode = chatMode === 'chat' ? 'reasoning' : 'chat';
      modeBtn.textContent = chatMode;
      modeBtn.dataset.mode = chatMode;
    });
  }

  // Conversation history sent to the backend (excludes the greeting bubble).
  const history = [];

  function openPanel() {
    panel.classList.add('open');
    panel.setAttribute('aria-hidden', 'false');
    toggle.classList.add('hidden');
    setTimeout(() => input.focus(), 200);
  }
  function closePanel() {
    panel.classList.remove('open');
    panel.setAttribute('aria-hidden', 'true');
    toggle.classList.remove('hidden');
  }

  toggle.addEventListener('click', openPanel);
  closeBtn.addEventListener('click', closePanel);
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && panel.classList.contains('open')) closePanel();
  });

  // Minimal, escaped markdown: ```code blocks```, `inline code`, line breaks.
  function escapeHtml(s) {
    return s.replace(/[&<>"']/g, c => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
  }
  function renderMarkdown(text) {
    const parts = text.split(/```/);
    return parts.map((part, i) => {
      if (i % 2 === 1) {                       // inside a fenced code block
        const body = part.replace(/^[a-zA-Z0-9]*\n/, '');
        return '<pre>' + escapeHtml(body) + '</pre>';
      }
      return escapeHtml(part)
        .replace(/`([^`]+)`/g, '<code>$1</code>')
        .replace(/\n/g, '<br>');
    }).join('');
  }

  function addMessage(role, text) {
    const div = document.createElement('div');
    div.className = 'chat-msg ' + role;
    div.innerHTML = renderMarkdown(text);
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
    return div;
  }

  async function send(text) {
    addMessage('user', text);
    history.push({ role: 'user', content: text });

    input.value = '';
    input.disabled = true;
    sendBtn.disabled = true;

    // Typing bubble with a live status list inside
    const typing = addMessage('assistant typing', 'thinking…');
    const statusList = document.createElement('div');
    statusList.className = 'chat-status-list';
    typing.appendChild(statusList);

    function addStatus(text, solved) {
      const item = document.createElement('div');
      item.className = 'chat-status-item' + (solved ? ' solved' : '');
      item.textContent = text;
      statusList.appendChild(item);
      log.scrollTop = log.scrollHeight;
    }

    try {
      const selectedModel = modelSelect ? modelSelect.value : null;
      const resp = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          messages: history,
          model: selectedModel,
          mode: chatMode,
          page_path: window.location.pathname,
        })
      });

      // Validation errors come back as plain JSON (non-200)
      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        typing.remove();
        addMessage('error', data.error || 'Something went wrong.');
        return;
      }

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';

      outer: while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split('\n');
        buf = lines.pop(); // keep incomplete last line

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          let event;
          try { event = JSON.parse(line.slice(6)); } catch { continue; }

          if (event.type === 'status') {
            addStatus(event.text, event.solved);

          } else if (event.type === 'error') {
            typing.remove();
            addMessage('error', event.error || 'Something went wrong.');
            break outer;

          } else if (event.type === 'done') {
            typing.remove();
            const raw = event.reply || '';
            const tagMatch = raw.match(/<create_challenge>([\s\S]*?)<\/create_challenge>/);
            const displayText = raw.replace(/<create_challenge>[\s\S]*?<\/create_challenge>/g, '').trim();
            if (displayText) {
              const msgEl = addMessage('assistant', displayText);
              if (event.mode === 'reasoning') {
                const badge = document.createElement('span');
                badge.className = 'reasoning-badge';
                badge.textContent = '⚙ reasoning';
                msgEl.prepend(badge);
              }
            }
            history.push({ role: 'assistant', content: raw });
            if (tagMatch) {
              try {
                showChallengeConfirm(JSON.parse(tagMatch[1].trim()));
              } catch (e) {
                addMessage('error', 'AI returned malformed challenge spec — could not parse JSON.');
              }
            }
            break outer;
          }
        }
      }
    } catch (e) {
      typing.remove();
      addMessage('error', 'Network error — is the server running?');
    } finally {
      input.disabled = false;
      sendBtn.disabled = false;
      input.focus();
    }
  }

  form.addEventListener('submit', e => {
    e.preventDefault();
    const text = input.value.trim();
    if (text) send(text);
  });

  function showChallengeConfirm(spec) {
    const existing = log.querySelector('.challenge-confirm-card');
    if (existing) existing.remove();

    const card = document.createElement('div');
    card.className = 'challenge-confirm-card';
    card.innerHTML = `
      <div class="confirm-card-header">⚡ New Challenge Ready</div>
      <div class="confirm-card-body">
        <div class="confirm-row"><span class="confirm-label">Name</span><span class="confirm-val">${escapeHtml(spec.name || '?')}</span></div>
        <div class="confirm-row"><span class="confirm-label">Type</span><span class="confirm-val">${escapeHtml(spec.vuln_type || '?')}</span></div>
        <div class="confirm-row"><span class="confirm-label">Difficulty</span><span class="confirm-val">${escapeHtml(spec.difficulty || '?')}</span></div>
        <div class="confirm-row"><span class="confirm-label">Points</span><span class="confirm-val">${escapeHtml(String(spec.points || '?'))}</span></div>
        <div class="confirm-row"><span class="confirm-label">Category</span><span class="confirm-val">${escapeHtml(spec.category || '?')}</span></div>
        ${spec.description ? `<div class="confirm-desc">${escapeHtml(spec.description)}</div>` : ''}
      </div>
      <div class="confirm-card-footer">
        <button class="btn btn-primary btn-sm confirm-create-btn">Create Challenge</button>
        <button class="btn btn-sm confirm-cancel-btn" style="background:transparent;border:1px solid #333;color:var(--text-dim)">Cancel</button>
      </div>`;

    log.appendChild(card);
    setTimeout(() => card.scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 50);

    card.querySelector('.confirm-cancel-btn').addEventListener('click', () => card.remove());

    card.querySelector('.confirm-create-btn').addEventListener('click', async () => {
      const createBtn = card.querySelector('.confirm-create-btn');
      createBtn.disabled = true;
      createBtn.textContent = 'Creating…';
      try {
        const r = await fetch('/api/add_challenge', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...spec, model: modelSelect ? modelSelect.value : '' })
        });
        const d = await r.json();
        if (d.success) {
          card.innerHTML = `
            <div class="confirm-card-header" style="color:var(--green);border-color:var(--green)">✓ Challenge Added</div>
            <div class="confirm-card-body">
              <div class="confirm-row"><span class="confirm-label">Name</span><span class="confirm-val">${escapeHtml(spec.name || '')}</span></div>
              <div class="confirm-row"><span class="confirm-label">URL</span><span class="confirm-val">${escapeHtml(d.url)}</span></div>
            </div>
            <div class="confirm-card-footer">
              <a href="${escapeHtml(d.url)}" class="btn btn-primary btn-sm" style="text-decoration:none">Open Challenge →</a>
              <a href="/" class="btn btn-sm" style="background:transparent;border:1px solid #333;color:var(--text-dim);text-decoration:none">← Homepage</a>
            </div>`;
        } else {
          createBtn.disabled = false;
          createBtn.textContent = 'Create Challenge';
          addMessage('error', 'Failed to create challenge: ' + escapeHtml(d.error || 'unknown error'));
        }
      } catch (e) {
        console.error('[create challenge]', e);
        createBtn.disabled = false;
        createBtn.textContent = 'Create Challenge';
        addMessage('error', 'Network error while creating challenge: ' + e.message);
      }
    });
  }
})();
