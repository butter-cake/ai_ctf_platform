// ── AI Post-Mortem analysis buttons ──────────────────────────────────────────
(function () {
  // Reuse the same safe markdown renderer as the chat panel.
  function escapeHtml(s) {
    return s.replace(/[&<>"']/g, c => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
  }
  function renderMarkdown(text) {
    // Fenced code blocks first (``` ... ```), then bold, inline code, line breaks.
    const parts = text.split(/```([a-z]*)\n?([\s\S]*?)```/g);
    let html = '';
    for (let i = 0; i < parts.length; i++) {
      if (i % 3 === 0) {
        // Plain text segment — apply bold, inline code, line breaks
        html += escapeHtml(parts[i])
          .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
          .replace(/`([^`]+)`/g, '<code>$1</code>')
          .replace(/\n/g, '<br>');
      } else if (i % 3 === 2) {
        // Code block body (lang tag is i%3===1, skip it for display)
        const lang = parts[i - 1] || '';
        const label = lang ? `<span class="code-block-lang">${escapeHtml(lang)}</span>` : '';
        html += `<div class="analysis-code-block">${label}<pre>${escapeHtml(parts[i])}</pre></div>`;
      }
    }
    return html;
  }

  document.querySelectorAll('.analyze-btn').forEach(btn => {
    btn.addEventListener('click', async function () {
      const username    = this.dataset.username;
      const challengeId = this.dataset.challenge;
      const panel       = document.getElementById('analysis-' + challengeId);
      if (!panel) return;

      // Toggle: if analysis is already showing, hide it.
      if (panel.style.display !== 'none') {
        panel.style.display = 'none';
        this.textContent = '>_ AI Post-Mortem';
        return;
      }

      this.disabled = true;
      this.textContent = '>_ Analyzing…';
      panel.style.display = 'block';
      panel.innerHTML = '<div class="analysis-loading">[ running post-mortem analysis… ]</div>';

      try {
        const resp = await fetch('/api/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, challenge_id: challengeId })
        });
        const data = await resp.json();

        if (!resp.ok || data.error) {
          panel.innerHTML = `<div class="analysis-error">Error: ${escapeHtml(data.error || 'Unknown error')}</div>`;
        } else {
          panel.innerHTML = `
            <div class="analysis-header">
              <span class="analysis-label">&gt;_ post-mortem analysis</span>
              <span class="analysis-model">${escapeHtml(data.model)}</span>
            </div>
            <div class="analysis-body">${renderMarkdown(data.analysis)}</div>`;
          this.textContent = '>_ Hide Analysis';
        }
      } catch (e) {
        panel.innerHTML = '<div class="analysis-error">Network error — is the server running?</div>';
      } finally {
        this.disabled = false;
        if (this.textContent === '>_ Analyzing…') this.textContent = '>_ AI Post-Mortem';
      }
    });
  });
})();
