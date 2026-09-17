// NetConfig Intelligence — frontend. No build step, no framework, no
// external requests: everything here only ever talks to this same origin.

const el = (id) => document.getElementById(id);
const RING_CIRCUMFERENCE = 2 * Math.PI * 54;

const EXAMPLES = {
  cisco: "! Deliberately insecure demo configuration for NetConfig Intelligence.\n! All credentials below are fake/sanitized demo values - do not reuse them.\nversion 12.4\nhostname EDGE-OLD\nenable password 7 094F471A1A0A\nusername admin password 7 08351A5C0713\n!\ninterface GigabitEthernet0/0\n ip address 192.168.1.1 255.255.255.0\n no shutdown\n!\ninterface GigabitEthernet0/1\n description WAN uplink\n ip address 203.0.113.10 255.255.255.252\n no shutdown\n!\ninterface GigabitEthernet0/2\n no shutdown\n!\nip http server\nsnmp-server community public RO\n!\naccess-list 101 permit ip any any\n!\nip access-list extended OPEN-ANY\n permit ip any any\n!\nline vty 0 4\n transport input telnet\n!\nend\n",
  mikrotik: "/system identity\nset name=BRANCH-MT\n/interface ethernet\nset [ find default-name=ether1 ] comment=\"WAN\"\n/ip address\nadd address=10.20.20.1/24 interface=ether2\nadd address=198.51.100.2/30 interface=ether1\n/ip service\nset telnet disabled=yes\nset ssh disabled=no address=10.20.20.0/24\n/user\nadd name=engineer group=full password=SANITIZED_DEMO_PASSWORD\n",
};

const DIFF_EXAMPLES = {
  "wan-change": {
    old: "hostname EDGE-RTR\n!\ninterface GigabitEthernet0/1\n description WAN uplink\n ip address 203.0.113.10 255.255.255.252\n no shutdown\n!\nip route 0.0.0.0 0.0.0.0 203.0.113.9\n!\nend\n",
    new: "hostname EDGE-RTR\n!\ninterface GigabitEthernet0/1\n description WAN uplink\n ip address 203.0.113.14 255.255.255.252\n no shutdown\n!\nip route 0.0.0.0 0.0.0.0 203.0.113.9\n!\nend\n",
  },
};

let sessionId = null;
let topologyLoadedFor = null;

// ---------- tabs ----------

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    const target = tab.dataset.tab;
    document.querySelectorAll(".tab-panel").forEach((panel) => {
      panel.hidden = panel.dataset.panel !== target;
    });
    if (target === "topology") loadTopology();
  });
});

// ---------- mode switch (analyze vs compare) ----------

document.querySelectorAll(".mode-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".mode-btn").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    const mode = btn.dataset.mode;
    document.querySelectorAll("[data-mode-panel]").forEach((panel) => {
      panel.hidden = panel.dataset.modePanel !== mode;
    });
  });
});

// ---------- example loaders ----------

document.querySelectorAll("[data-example]").forEach((btn) => {
  btn.addEventListener("click", () => {
    const form = el("analyze-form");
    form.text.value = EXAMPLES[btn.dataset.example];
    form.vendor.value = "auto";
    form.text.focus();
  });
});

document.querySelectorAll("[data-diff-example]").forEach((btn) => {
  btn.addEventListener("click", () => {
    const form = el("diff-form");
    const ex = DIFF_EXAMPLES[btn.dataset.diffExample];
    form.old_text.value = ex.old;
    form.new_text.value = ex.new;
    form.vendor.value = "auto";
    form.old_text.focus();
  });
});

// ---------- rendering helpers ----------

function renderScore(score) {
  const offset = RING_CIRCUMFERENCE * (1 - score / 100);
  const ring = el("ring-fg");
  ring.style.strokeDashoffset = String(offset);
  ring.style.stroke =
    score >= 80 ? "var(--accent)" : score >= 50 ? "var(--medium)" : "var(--critical)";
  el("score").textContent = score;
}

function escapeHtml(str) {
  return String(str ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function renderFindings(findings) {
  if (!findings.length) {
    el("findings").innerHTML = '<p class="empty-note">No implemented rules fired for this configuration.</p>';
    return;
  }
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const sorted = [...findings].sort((a, b) => order[a.severity] - order[b.severity]);
  el("findings").innerHTML = sorted
    .map(
      (f) => `
      <article class="finding ${f.severity}">
        <div class="finding-head">
          <span class="sev-badge ${f.severity}">${f.severity}</span>
          <span class="finding-title">${escapeHtml(f.title)}</span>
          ${f.subject ? `<span class="finding-subject">${escapeHtml(f.subject)}</span>` : ""}
        </div>
        <p class="finding-desc">${escapeHtml(f.description)}</p>
        <p class="finding-rec"><b>Fix</b> — ${escapeHtml(f.recommendation)}</p>
      </article>`
    )
    .join("");
}

function renderValidation(data) {
  el("validation").innerHTML = data.checks
    .map(
      (c) => `
      <div class="check-item ${c.status}">
        <span class="check-icon">${c.status === "pass" ? "✓" : c.status === "warning" ? "!" : "✕"}</span>
        <div>
          <p class="check-name">${escapeHtml(c.name)}</p>
          <p class="check-detail">${escapeHtml(c.detail)}</p>
        </div>
      </div>`
    )
    .join("");
}

function renderReplay(data) {
  el("replay-meta").innerHTML = `${escapeHtml(data.notice)}<br><b>${escapeHtml(data.target_platform)}</b> — ${escapeHtml(data.compatibility_warning)}`;
  el("replay").innerHTML = data.steps
    .map(
      (s) => `
      <li class="replay-step">
        <span class="step-num">${String(s.step).padStart(2, "0")}</span>
        <div>
          <div class="step-cmd">${escapeHtml(s.command)}</div>
          <div class="step-explain">${escapeHtml(s.explanation)}</div>
          ${s.dependencies.length ? `<div class="step-deps">depends on: ${s.dependencies.map(escapeHtml).join(", ")}</div>` : ""}
        </div>
        <span class="risk-badge ${s.risk}">${s.risk}</span>
      </li>`
    )
    .join("");
}

async function loadSupportingViews() {
  if (!sessionId) return;
  const [validation, replay] = await Promise.all(
    ["validation", "replay"].map((path) => fetch(`/api/sessions/${sessionId}/${path}`).then((r) => r.json()))
  );
  renderValidation(validation);
  renderReplay(replay);
}

async function loadTopology() {
  if (!sessionId || topologyLoadedFor === sessionId) return;
  el("topology").innerHTML = '<p class="topology-empty">Drawing…</p>';
  const response = await fetch(`/api/sessions/${sessionId}/topology`);
  const data = await response.json();
  el("topology").innerHTML = data.svg || '<p class="topology-empty">Nothing to draw for this configuration.</p>';
  topologyLoadedFor = sessionId;
}

// ---------- analyze ----------

el("analyze-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  el("error").textContent = "";
  el("revealed").hidden = true;

  const response = await fetch("/api/analyze", { method: "POST", body: new FormData(event.target) });
  const data = await response.json();
  if (!response.ok) {
    el("error").textContent = data.detail || "Analysis failed.";
    return;
  }

  sessionId = data.session_id;
  topologyLoadedFor = null;
  el("diff-results").hidden = true;
  el("results").hidden = false;
  el("hostname").textContent = data.hostname;
  el("vendor").textContent = data.vendor.replaceAll("_", " ");
  renderScore(data.health.overall);
  el("score-detail").textContent = `${data.health.total_findings} finding(s)`;
  el("sensitive").textContent = `${data.summary.total} detected`;
  el("secret-detail").textContent = `${data.summary.credentials} credential(s) · ${data.summary.reversible_count} recoverable locally`;
  el("config").textContent = data.sanitized;
  el("download-sanitized").href = `/api/sessions/${sessionId}/export/sanitized`;
  el("download-anonymized").href = `/api/sessions/${sessionId}/export/anonymized`;
  renderFindings(data.findings);
  await loadSupportingViews();
  el("results").scrollIntoView({ behavior: "smooth", block: "start" });
});

// ---------- reveal / hide ----------

el("reveal").addEventListener("click", async () => {
  if (!sessionId) return;
  if (!confirm("Show recoverable passwords only in this local browser session? Do not share this screen.")) return;
  const form = new FormData();
  form.append("acknowledged", "true");
  const response = await fetch(`/api/sessions/${sessionId}/reveal`, { method: "POST", body: form });
  const data = await response.json();
  el("credential-list").textContent = data.credentials.length
    ? data.credentials.map((x) => `${x.context || x.type}: ${x.value}`).join("\n")
    : "No recoverable plaintext or Cisco type 7 values were found.";
  el("revealed").hidden = false;
});

el("hide").addEventListener("click", () => {
  el("credential-list").textContent = "";
  el("revealed").hidden = true;
});

// ---------- compare two configs ----------

function renderDiffLines(unified) {
  if (!unified) return '<p class="diff-empty">No differences — both configurations render identically.</p>';
  return unified
    .split("\n")
    .map((line) => {
      let cls = "meta";
      if (line.startsWith("+++") || line.startsWith("---")) cls = "meta";
      else if (line.startsWith("@@")) cls = "hunk";
      else if (line.startsWith("+")) cls = "add";
      else if (line.startsWith("-")) cls = "remove";
      return `<div class="diff-line ${cls}">${escapeHtml(line) || "&nbsp;"}</div>`;
    })
    .join("");
}

el("diff-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  el("diff-error").textContent = "";

  const response = await fetch("/api/diff", { method: "POST", body: new FormData(event.target) });
  const data = await response.json();
  if (!response.ok) {
    el("diff-error").textContent = data.detail || "Comparison failed.";
    return;
  }

  el("results").hidden = true;
  el("diff-results").hidden = false;
  el("diff-old-hostname").textContent = data.old.hostname;
  el("diff-old-vendor").textContent = data.old.vendor.replaceAll("_", " ");
  el("diff-new-hostname").textContent = data.new.hostname;
  el("diff-new-vendor").textContent = data.new.vendor.replaceAll("_", " ");
  el("diff-stats").textContent = `+${data.added} / -${data.removed}`;
  el("diff-mismatch-warning").innerHTML = data.vendor_mismatch
    ? '<span class="diff-mismatch">Different vendors detected — comparison may be noisy.</span>'
    : "";
  el("diff-output").innerHTML = renderDiffLines(data.unified);
  el("diff-results").scrollIntoView({ behavior: "smooth", block: "start" });
});
