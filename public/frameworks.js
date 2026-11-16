// Threat Hunting Frameworks tab. Its own mode (selectMode('frameworks')).
// Two jobs: (1) a one-screen reference outline of the established hunting
// frameworks and the models they lean on, and (2) a worksheet that walks the
// phases of whichever framework you pick and compiles your answers into a
// copyable hunt plan. Pure client-side reference content — uses escHtml and
// copy from the inline script; nothing is sent to the server.

// ── Process frameworks (each drives the worksheet) ──────────────────────────
var FRAMEWORKS = [
  {
    id: 'peak', name: 'PEAK', full: 'Prepare, Execute, Act with Knowledge',
    origin: 'Splunk — David Bianco & Ryan Fetterman, 2023',
    use: 'General-purpose, repeatable hunt lifecycle. Supports three hunt types: hypothesis-driven, baseline (exploratory data analysis), and model-assisted (M-ATH).',
    phases: [
      { name: 'Prepare', desc: 'Scope the hunt and set it up to succeed.', prompts: [
        'Hunt topic / hypothesis — what are you looking for, and why now?',
        'Driver — the ATT&CK technique(s), threat intel, or anomaly behind it?',
        'Scope — data sources, systems, and timeframe?',
        'Hunt type — hypothesis-driven, baseline (EDA), or model-assisted?',
        'Success criteria — what outcome ends the hunt?' ] },
      { name: 'Execute', desc: 'Gather and analyze the data; follow the leads.', prompts: [
        'Queries / analytics run (note the platform for each)?',
        'Findings and anomalies observed?',
        'Pivots and enrichment followed?',
        'Evidence collected?' ] },
      { name: 'Act with Knowledge', desc: 'Turn the hunt into lasting value.', prompts: [
        'Verdict — malicious, benign, or inconclusive?',
        'New detections or analytics to engineer?',
        'Visibility / data gaps discovered?',
        'Handoffs and who to brief (IR, detection eng, leadership)?',
        'Documentation and lessons learned?' ] },
    ],
  },
  {
    id: 'tahiti', name: 'TaHiTI', full: 'Targeted Hunting integrating Threat Intelligence',
    origin: 'Dutch FI-ISAC, 2018',
    use: 'Intel-led hunting with a reusable hypothesis backlog. Strong fit where cyber threat intelligence feeds the hunt program.',
    phases: [
      { name: 'Initiate', desc: 'Turn a trigger into a stored, prioritized hypothesis.', prompts: [
        'Trigger — TI report, alert, red-team result, or anomaly?',
        'Hypothesis — a concise, testable statement?',
        'Backlog abstract — short summary stored for reuse?',
        'Priority and ATT&CK mapping?' ] },
      { name: 'Hunt', desc: 'Refine and investigate the hypothesis.', prompts: [
        'Refine the hypothesis into specific, testable claims?',
        'Data sources and queries to investigate?',
        'Threat intelligence used to steer the hunt?',
        'Findings — does the evidence confirm or reject it?' ] },
      { name: 'Finalize', desc: 'Document, report, and improve.', prompts: [
        'Results and conclusion?',
        'New detections / use cases to create?',
        'Report and stakeholders?',
        'Lessons learned and backlog updates?' ] },
    ],
  },
  {
    id: 'loop', name: 'Threat Hunting Loop', full: 'Sqrrl hunting loop — David Bianco',
    origin: 'Sqrrl / David Bianco',
    use: 'The classic four-stage cycle. Lightweight mental model for a single hunt that feeds its results back into detection.',
    phases: [
      { name: 'Create Hypotheses', desc: 'State what you believe might be happening.', prompts: [
        'Hypothesis — intel-driven, situational-awareness-driven, or analytics-driven?' ] },
      { name: 'Investigate via Tools & Techniques', desc: 'Test it against data.', prompts: [
        'Tools and data to use (search, stack counting / frequency analysis, clustering, ML)?' ] },
      { name: 'Uncover New Patterns & TTPs', desc: 'Find the adversary behavior.', prompts: [
        'New TTPs or patterns the investigation revealed?' ] },
      { name: 'Inform & Enrich Analytics', desc: 'Feed results back in.', prompts: [
        'Automated detections / enrichments that result and loop back?' ] },
    ],
  },
  {
    id: 'attack', name: 'ATT&CK-driven', full: 'MITRE ATT&CK technique-led hunting',
    origin: 'MITRE ATT&CK',
    use: 'Pick a technique, model how it shows up in your telemetry, hunt it, then measure coverage. Great for closing mapped visibility gaps.',
    phases: [
      { name: 'Select Technique', desc: 'Choose what to hunt and why.', prompts: [
        'Tactic and technique (ID) you are hunting?',
        'Why this one — threat profile, recent intel, or crown-jewel relevance?' ] },
      { name: 'Understand Behavior', desc: 'Learn how it manifests.', prompts: [
        'How does the technique show up (procedures, tools)?',
        'Which ATT&CK data sources / components reveal it?' ] },
      { name: 'Develop Analytic', desc: 'Write the detection logic.', prompts: [
        'Query / analytic that detects the behavior (per platform)?',
        'Baseline of normal to separate signal from noise?' ] },
      { name: 'Hunt & Validate', desc: 'Run it and judge the hits.', prompts: [
        'Findings?',
        'True vs. false positives — how will you tune?' ] },
      { name: 'Operationalize', desc: 'Make it durable.', prompts: [
        'Promote to a scheduled detection? Update the ATT&CK coverage heatmap?' ] },
    ],
  },
  {
    id: 'ddm', name: 'Data-Driven', full: 'Data-Driven Methodology (DDM) — Roberto Rodriguez',
    origin: 'Open Threat Research / ThreatHunter-Playbook',
    use: 'Research-grade method: model your data, emulate the adversary, write detection logic, and validate it fired. Best when you can generate the behavior safely.',
    phases: [
      { name: 'Define Research Goal', desc: 'Frame the question.', prompts: [
        'Adversary behavior or question you are researching?' ] },
      { name: 'Model Data', desc: 'Map behavior to telemetry.', prompts: [
        'Which data sources and fields model that behavior (data dictionaries)?' ] },
      { name: 'Emulate Adversary', desc: 'Generate the behavior.', prompts: [
        'How will you produce it safely (atomic test, red team, emulation plan)?' ] },
      { name: 'Define Detection Logic', desc: 'Write the hunt.', prompts: [
        'Hunt / detection logic that identifies it in the modeled data?' ] },
      { name: 'Validate Detection', desc: 'Prove it works.', prompts: [
        'Did it fire on the emulation? False-positive rate? Document and share.' ] },
    ],
  },
  {
    id: 'f3ead', name: 'F3EAD', full: 'Find, Fix, Finish, Exploit, Analyze, Disseminate',
    origin: 'Military targeting cycle, adapted to intel-driven hunting',
    use: 'Operationalizes hunting with an intelligence cycle — pairs an operations half (F3) with an intel half (EAD) so each hunt produces reusable intelligence.',
    phases: [
      { name: 'Find', desc: 'Pick the target.', prompts: [
        'Target or threat to pursue (from intel requirements)?' ] },
      { name: 'Fix', desc: 'Locate it in your data.', prompts: [
        'Where and when does the activity appear in your telemetry?' ] },
      { name: 'Finish', desc: 'Act on it.', prompts: [
        'Action taken — contain, eradicate, or keep monitoring?' ] },
      { name: 'Exploit', desc: 'Harvest the artifacts.', prompts: [
        'IOCs, artifacts, and TTPs gathered from the activity?' ] },
      { name: 'Analyze', desc: 'Make sense of them.', prompts: [
        'What did analysis reveal (scope, attribution, related activity)?' ] },
      { name: 'Disseminate', desc: 'Share the product.', prompts: [
        'Who receives the intelligence and detections produced?' ] },
    ],
  },
];

// ── Reference models (outline only) ─────────────────────────────────────────
var FW_MODELS = [
  { name: 'Hunting Maturity Model (HMM)', by: 'David Bianco',
    note: 'Where your program sits — aim to automate the repeatable.',
    rows: ['HMM0 Initial — rely on automated alerting', 'HMM1 Minimal — routine TI + basic searches',
      'HMM2 Procedural — follow others’ procedures', 'HMM3 Innovative — create your own procedures',
      'HMM4 Leading — automate the repeatable'] },
  { name: 'Pyramid of Pain', by: 'David Bianco',
    note: 'Hunt high on the pyramid — the higher you go, the more it hurts the adversary.',
    rows: ['Hash values (trivial)', 'IP addresses (easy)', 'Domain names (simple)',
      'Network / host artifacts (annoying)', 'Tools (challenging)', 'TTPs (tough)'] },
  { name: 'Cyber Kill Chain', by: 'Lockheed Martin',
    note: 'Seven intrusion phases — hunt for evidence at each link.',
    rows: ['Reconnaissance', 'Weaponization', 'Delivery', 'Exploitation', 'Installation',
      'Command & Control', 'Actions on Objectives'] },
  { name: 'Diamond Model', by: 'Caltagirone, Pendergast, Betz',
    note: 'Pivot across the four vertices to expand an intrusion.',
    rows: ['Adversary', 'Capability', 'Infrastructure', 'Victim'] },
];

var _fwSel = null;

function loadFrameworks() {
  if (_fwSel) return; // already built
  try { _fwSel = localStorage.getItem('lth_fw_sel') || 'peak'; } catch (e) { _fwSel = 'peak'; }
  if (!FRAMEWORKS.some(function (f) { return f.id === _fwSel; })) _fwSel = 'peak';
  fwRenderModels();
  fwRenderSelector();
  fwRenderBody();
}

function fwRenderModels() {
  var el = document.getElementById('fwModels');
  if (!el) return;
  var h = '';
  for (var i = 0; i < FW_MODELS.length; i++) {
    var m = FW_MODELS[i];
    h += '<div class="fw-model"><div class="fw-model-h">' + escHtml(m.name) +
      ' <span>' + escHtml(m.by) + '</span></div><div class="fw-model-note">' + escHtml(m.note) + '</div><ol>';
    for (var j = 0; j < m.rows.length; j++) h += '<li>' + escHtml(m.rows[j]) + '</li>';
    h += '</ol></div>';
  }
  el.innerHTML = h;
}

function fwRenderSelector() {
  var el = document.getElementById('fwSelector');
  if (!el) return;
  var h = '';
  for (var i = 0; i < FRAMEWORKS.length; i++) {
    var f = FRAMEWORKS[i];
    h += '<span class="fw-pill' + (f.id === _fwSel ? ' on' : '') + '" onclick="fwSelect(\'' +
      f.id + '\')"><b>' + escHtml(f.name) + '</b> ' + escHtml(f.full) + '</span>';
  }
  el.innerHTML = h;
}

function fwCurrent() {
  for (var i = 0; i < FRAMEWORKS.length; i++) if (FRAMEWORKS[i].id === _fwSel) return FRAMEWORKS[i];
  return FRAMEWORKS[0];
}

function fwWB() {
  try { return JSON.parse(localStorage.getItem('lth_fw_wb') || '{}'); } catch (e) { return {}; }
}

function fwRenderBody() {
  var el = document.getElementById('fwBody');
  if (!el) return;
  var f = fwCurrent();
  var wb = fwWB();
  var mine = wb[f.id] || {};
  var h = '<div class="panel" style="margin-bottom:12px;"><div class="panel-header">' +
    escHtml(f.name) + ' — ' + escHtml(f.full) + '</div><div class="panel-body">' +
    '<div class="fw-origin">' + escHtml(f.origin) + '</div>' +
    '<div class="fw-use">' + escHtml(f.use) + '</div></div></div>';

  for (var i = 0; i < f.phases.length; i++) {
    var p = f.phases[i];
    var val = mine[p.name] || '';
    h += '<div class="panel fw-phase" style="margin-bottom:10px;"><div class="panel-header">' +
      '<span class="fw-num">' + (i + 1) + '</span><span style="flex:1;">' + escHtml(p.name) + '</span>' +
      '<span class="fw-phase-desc">' + escHtml(p.desc) + '</span></div><div class="panel-body">';
    h += '<ul class="fw-prompts">';
    for (var j = 0; j < p.prompts.length; j++) h += '<li>' + escHtml(p.prompts[j]) + '</li>';
    h += '</ul>';
    h += '<textarea class="fw-input" rows="3" placeholder="Your notes for this phase..." ' +
      'oninput="fwSave(\'' + escHtml(p.name) + '\',this.value)">' + escHtml(val) + '</textarea>';
    h += '</div></div>';
  }
  el.innerHTML = h;
}

function fwSelect(id) {
  _fwSel = id;
  try { localStorage.setItem('lth_fw_sel', id); } catch (e) {}
  fwRenderSelector();
  fwRenderBody();
}

function fwSave(phase, val) {
  var f = fwCurrent();
  var wb = fwWB();
  if (!wb[f.id]) wb[f.id] = {};
  wb[f.id][phase] = val;
  try { localStorage.setItem('lth_fw_wb', JSON.stringify(wb)); } catch (e) {}
}

// Compile the filled worksheet into a copyable hunt plan.
function fwCompile() {
  var f = fwCurrent();
  var wb = fwWB();
  var mine = wb[f.id] || {};
  var out = '# ' + f.name + ' hunt plan — ' + new Date().toISOString().slice(0, 10) + '\n';
  out += 'Framework: ' + f.full + '  (' + f.origin + ')\n';
  for (var i = 0; i < f.phases.length; i++) {
    var p = f.phases[i];
    out += '\n## ' + (i + 1) + '. ' + p.name + '\n';
    out += (mine[p.name] && mine[p.name].trim()) ? mine[p.name].trim() + '\n' : '_(not filled in)_\n';
  }
  var ta = document.getElementById('fwPlan');
  ta.value = out;
  ta.style.display = '';
  document.getElementById('fwCopyBtn').style.display = '';
}

function fwCopyPlan(btn) {
  var ta = document.getElementById('fwPlan');
  if (ta && ta.value) copy(ta.value);
}

function fwClear() {
  var f = fwCurrent();
  var wb = fwWB();
  delete wb[f.id];
  try { localStorage.setItem('lth_fw_wb', JSON.stringify(wb)); } catch (e) {}
  var ta = document.getElementById('fwPlan');
  if (ta) { ta.value = ''; ta.style.display = 'none'; }
  var b = document.getElementById('fwCopyBtn'); if (b) b.style.display = 'none';
  fwRenderBody();
}
