(() => {
  const feed = document.getElementById('feed');
  const conn = document.getElementById('conn');
  const gwEl = document.getElementById('gw');
  const resultEl = document.getElementById('scenario-result');
  const autoScroll = document.getElementById('auto-scroll');
  const clearBtn = document.getElementById('clear-feed');

  const VERDICT_EMOJI = {
    ALLOWED: '✅',
    DENIED: '⛔',
    REPLAYED: '🔁',
    SANITIZED: '🩹',
    SUSPENDED_HITL: '⏸',
    EXECUTED_HITL: '✅',
    APPROVED_HITL: '🟢',
    REJECTED_HITL: '🔴',
    UPSTREAM_ERROR: '💥',
  };

  const stats = {
    total: 0,
    ALLOWED: 0, DENIED: 0, REPLAYED: 0, SANITIZED: 0,
    SUSPENDED_HITL: 0, EXECUTED_HITL: 0,
  };

  function bumpStats(verdict) {
    stats.total += 1;
    if (stats[verdict] !== undefined) stats[verdict] += 1;
    for (const [k, v] of Object.entries(stats)) {
      const el = document.getElementById(`stat-${k}`);
      if (el) el.textContent = v;
    }
  }

  function fmtTs(iso) {
    try {
      const d = new Date(iso);
      return d.toLocaleTimeString([], { hour12: false });
    } catch (_) { return iso; }
  }

  function emptyFeed() {
    const empty = feed.querySelector('.empty');
    if (empty) empty.remove();
  }

  function addEvent(ev) {
    emptyFeed();
    const row = document.createElement('div');
    row.className = `event v-${ev.verdict || 'UNKNOWN'}`;
    const findings = (ev.sanitized_findings || [])
      .map(f => `${f.rule}×${f.count}`).join(', ');
    row.innerHTML = `
      <div class="ts">${fmtTs(ev.ts)}</div>
      <div><span class="badge">${VERDICT_EMOJI[ev.verdict] || ''} ${ev.verdict}</span></div>
      <div class="tool" title="${escape(ev.tool_name || ev.path)}">${escape(ev.tool_name || ev.path || '—')}</div>
      <div>
        <div class="rule" title="${escape(ev.reason || '')}">${escape(ev.rule || '')}${ev.ticket_id ? ' · ' + ev.ticket_id.slice(0, 8) : ''}</div>
        ${findings ? `<div class="findings">DLP: ${escape(findings)}</div>` : ''}
      </div>
      <div class="ms">${(ev.latency_ms ?? 0).toFixed(1)}ms</div>
    `;
    feed.appendChild(row);
    const rows = feed.querySelectorAll('.event');
    if (rows.length > 400) rows[0].remove();
    if (autoScroll.checked) feed.scrollTop = feed.scrollHeight;
    bumpStats(ev.verdict);
  }

  function escape(s) {
    if (s === undefined || s === null) return '';
    return String(s).replace(/[&<>"']/g, c => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
  }

  function openStream() {
    const es = new EventSource('/api/stream');
    es.onopen = () => { conn.textContent = 'live'; conn.classList.remove('off'); conn.classList.add('on'); };
    es.onerror = () => {
      conn.textContent = 'reconnecting…';
      conn.classList.remove('on'); conn.classList.add('off');
      es.close();
      setTimeout(openStream, 2000);
    };
    es.onmessage = (msg) => {
      try { addEvent(JSON.parse(msg.data)); } catch (_) { /* heartbeat */ }
    };
  }

  document.querySelectorAll('.btn[data-scenario]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const name = btn.dataset.scenario;
      btn.disabled = true;
      resultEl.classList.remove('hidden');
      resultEl.textContent = `▶ running scenario "${name}" …`;
      try {
        const r = await fetch(`/api/scenario/${name}`, { method: 'POST' });
        const data = await r.json();
        resultEl.textContent = `✓ scenario "${name}" completed\n\n` + JSON.stringify(data.steps, null, 2);
      } catch (err) {
        resultEl.textContent = `✗ scenario failed: ${err}`;
      } finally {
        btn.disabled = false;
      }
    });
  });

  clearBtn.addEventListener('click', () => {
    feed.innerHTML = '';
    for (const k of Object.keys(stats)) stats[k] = 0;
    for (const k of Object.keys(stats)) {
      const el = document.getElementById(`stat-${k}`); if (el) el.textContent = 0;
    }
  });

  gwEl.textContent = window.location.origin;
  openStream();
})();
