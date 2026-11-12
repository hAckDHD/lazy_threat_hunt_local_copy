// ═══ DETECTION ENGINEERING ═══
var detectIOCs = [];
var detectMode = 'custom';

// TYPE_ICONS is already declared in the inline script (server.ts)

function detectIOCType(val) {
  val = val.trim();
  if (/^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$/.test(val)) return 'ip';
  if (/^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/.test(val) || /^([0-9a-fA-F]{1,4}:)*::([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$/.test(val)) return 'ipv6';
  if (/^CVE-\d{4}-\d{4,}$/i.test(val)) return 'cve';
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val)) return 'email';
  if (/^https?:\/\//i.test(val)) return 'url';
  if (/^[a-fA-F0-9]{64}$/.test(val)) return 'sha256';
  if (/^[a-fA-F0-9]{40}$/.test(val)) return 'sha1';
  if (/^[a-fA-F0-9]{32}$/.test(val)) return 'md5';
  if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(val)) return 'domain';
  return null;
}

function setDetectMode(mode) {
  detectMode = mode;
  var isCustom = mode === 'custom';
  var isDB = mode === 'db';
  var isHunt = mode === 'hunt';
  var cc = document.getElementById('detectCustomControls');
  var dc = document.getElementById('detectDbControls');
  var hc = document.getElementById('detectHuntControls');
  if (cc) cc.style.display = isCustom ? '' : 'none';
  if (dc) dc.style.display = isDB ? '' : 'none';
  if (hc) hc.style.display = isHunt ? '' : 'none';
  // These three buttons never actually reflected which mode was selected
  // before — "Custom IOCs" just had a hardcoded border-color in the HTML
  // that never changed on click. Now that they're .hc-toggle, toggling
  // .active is what makes the selected one show as filled/glitched.
  var custom = document.getElementById('detectModeCustom');
  var db = document.getElementById('detectModeDB');
  var huntBtn = document.getElementById('detectModeHunt');
  if (custom) custom.classList.toggle('active', isCustom);
  if (db) db.classList.toggle('active', isDB);
  if (huntBtn) huntBtn.classList.toggle('active', isHunt);
  if (isHunt) updateDetectHuntCount();
}

function updateDetectHuntCount() {
  var el = document.getElementById('detectHuntCount');
  if (!el) return;
  var count = (typeof huntIOCs !== 'undefined' && huntIOCs) ? huntIOCs.length : 0;
  el.textContent = count + ' IOC(s) in current hunt';
  el.style.color = count > 0 ? 'var(--green)' : 'var(--text2)';
}

function detectAddOne() {
  var inp = document.getElementById('detectAddVal');
  var typeEl = document.getElementById('detectAddType');
  var val = inp.value.trim();
  if (!val) return;
  var type = typeEl.value === 'auto' ? (detectIOCType(val) || 'hostname') : typeEl.value;
  for (var i = 0; i < detectIOCs.length; i++) { if (detectIOCs[i].value === val) { inp.value = ''; return; } }
  detectIOCs.push({value: val, type: type});
  inp.value = '';
  updateDetectBlocks();
}

function detectPastePreview() {
  var raw = document.getElementById('detectPasteInput').value;
  var lines = raw.split(/[\n,;]+/);
  var ok = 0, skip = 0;
  for (var i = 0; i < lines.length; i++) { var l = lines[i].trim(); if (!l) continue; detectIOCType(l) ? ok++ : skip++; }
  document.getElementById('detectPasteInfo').innerHTML =
    ok ? '<span style="color:var(--green)">✓ ' + ok + ' recognized</span>' + (skip ? '<span style="color:var(--yellow)"> · ' + skip + ' unrecognized</span>' : '') : '';
}

function detectPasteAdd() {
  var raw = document.getElementById('detectPasteInput').value;
  var lines = raw.split(/[\n,;]+/);
  for (var i = 0; i < lines.length; i++) {
    var l = lines[i].trim(); if (!l) continue;
    var found = false;
    for (var j = 0; j < detectIOCs.length; j++) { if (detectIOCs[j].value === l) { found = true; break; } }
    if (found) continue;
    var type = detectIOCType(l);
    if (!type) { var a = prompt('Cannot auto-detect type for:\n' + l + '\n\nEnter type or leave blank to skip:'); if (!a || !a.trim()) continue; type = a.trim().toLowerCase(); }
    detectIOCs.push({value: l, type: type});
  }
  document.getElementById('detectPasteInput').value = '';
  document.getElementById('detectPasteInfo').innerHTML = '';
  updateDetectBlocks();
}

function updateDetectBlocks() {
  var container = document.getElementById('detectBlocks');
  var countEl = document.getElementById('detectBlockCount');
  if (!detectIOCs.length) { container.innerHTML = '<span style="color:var(--text2);font-size:11px;">No IOCs added yet</span>'; countEl.textContent = ''; return; }
  var TYPE_ORDER = ['ip','ipv6','domain','url','sha256','sha1','md5','email','cve','filename','registry_key','hostname'];
  var groups = {};
  for (var i = 0; i < detectIOCs.length; i++) { var t = detectIOCs[i].type; if (!groups[t]) groups[t] = []; groups[t].push(detectIOCs[i].value); }
  var sortedTypes = [];
  for (var i = 0; i < TYPE_ORDER.length; i++) { if (groups[TYPE_ORDER[i]]) sortedTypes.push(TYPE_ORDER[i]); }
  for (var t in groups) { if (sortedTypes.indexOf(t) === -1) sortedTypes.push(t); }
  var html = '';
  for (var i = 0; i < sortedTypes.length; i++) {
    var type = sortedTypes[i];
    html += '<div style="margin-bottom:7px;"><div style="font-size:10px;color:var(--purple);font-weight:700;text-transform:uppercase;margin-bottom:3px;">' + (TYPE_ICONS[type]||'•') + ' ' + escHtml(type) + ' (' + groups[type].length + ')</div>';
    for (var j = 0; j < groups[type].length; j++) {
      var val = groups[type][j];
      html += '<div style="display:flex;align-items:center;gap:5px;padding:2px 6px;border-radius:3px;background:var(--bg2);margin-bottom:2px;font-size:11px;">' +
        '<span style="font-family:monospace;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + escHtml(val) + '">' + escHtml(val) + '</span>' +
        '<span style="color:var(--red);cursor:pointer;padding:0 4px;font-weight:700;font-size:13px;" onclick="detectRemoveIOC(' + escHtml(JSON.stringify(val)) + ')">×</span></div>';
    }
    html += '</div>';
  }
  container.innerHTML = html;
  var byType = {};
  for (var i = 0; i < detectIOCs.length; i++) { var t = detectIOCs[i].type; byType[t] = (byType[t]||0) + 1; }
  var parts = [];
  for (var t in byType) parts.push(byType[t] + ' ' + t);
  countEl.textContent = detectIOCs.length + ' IOC(s): ' + parts.join(', ');
}

function detectRemoveIOC(val) {
  var newArr = [];
  for (var i = 0; i < detectIOCs.length; i++) { if (detectIOCs[i].value !== val) newArr.push(detectIOCs[i]); }
  detectIOCs = newArr;
  updateDetectBlocks();
}

function detectClearBlocks() { detectIOCs = []; updateDetectBlocks(); }

function detectLoadFromHunt() {
  if (typeof huntIOCs === 'undefined' || !huntIOCs || !huntIOCs.length) {
    alert('No IOCs in current hunt. Run a hunt first, then come back here.');
    return;
  }
  var loaded = 0, skipped = 0;
  for (var i = 0; i < huntIOCs.length; i++) {
    var val = huntIOCs[i].value;
    var type = huntIOCs[i].type;
    var found = false;
    for (var j = 0; j < detectIOCs.length; j++) { if (detectIOCs[j].value === val) { found = true; break; } }
    if (found) { skipped++; continue; }
    detectIOCs.push({value: val, type: type});
    loaded++;
  }
  updateDetectBlocks();
  updateDetectHuntCount();
  var msg = 'Loaded ' + loaded + ' IOC(s) from hunt';
  if (skipped) msg += ' (' + skipped + ' duplicate(s) skipped)';
  var div = document.getElementById('detectResults');
  if (div) div.innerHTML = '<span style="color:var(--green);font-weight:700;">' + msg + '</span>. Click Generate Rules when ready.';
}

var _detectRuleCache = [];

async function buildDetectionRules() {
  var platform = document.getElementById('detectPlatform').value;
  var div = document.getElementById('detectResults');
  div.innerHTML = '<div class="loading">Generating detection rules…</div>';
  var rawIOCs;
  if (detectMode === 'custom' || detectMode === 'hunt') {
    if (!detectIOCs.length) { div.innerHTML = '<div class="loading">No IOCs in list.</div>'; return; }
    rawIOCs = detectIOCs;
  } else {
    var clsVal = document.getElementById('detectClassFilter').value;
    var cls = clsVal === 'all' ? [] : clsVal.split(',');
    var checkedTypes = [];
    var cbs = document.querySelectorAll('#detectTypeGrid input:checked');
    for (var i = 0; i < cbs.length; i++) checkedTypes.push(cbs[i].value);
    if (!checkedTypes.length) { div.innerHTML = '<div class="loading">Select at least one type.</div>'; return; }
    var qs = new URLSearchParams();
    qs.set('type', checkedTypes.join(','));
    if (cls.length) qs.set('classification', cls.join(','));
    qs.set('limit', '2000');
    var data = await api('/api/iocs?' + qs);
    var iocs = data.iocs || [];
    if (!iocs.length) { div.innerHTML = '<div class="loading">No matching IOCs in DB.</div>'; return; }
    rawIOCs = [];
    for (var i = 0; i < iocs.length; i++) rawIOCs.push({value: iocs[i].value, type: iocs[i].type});
  }
  var data = await api('/api/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({platform:platform, rawIOCs:rawIOCs})});
  if (!data.rules || !data.rules.length) { div.innerHTML = '<div class="loading">No rules generated.</div>'; return; }
  _detectRuleCache = data.rules;
  var DET_PN = {sigma:'Sigma', kql:'KQL Analytics Rule', splunk:'Splunk Correlation', elastic:'Elastic Detection'};
  var DET_SC = {critical:'var(--red)', high:'var(--orange)', medium:'var(--yellow)', low:'var(--green)'};
  var html = '<div style="font-size:11px;color:var(--text2);margin-bottom:10px;display:flex;align-items:center;gap:10px;">' +
    data.rules.length + ' rule(s) generated ' +
    '<button class="secondary" style="font-size:11px;padding:3px 10px;" onclick="copyAllDetectRules()">⧉ Copy All</button></div>';
  for (var idx = 0; idx < data.rules.length; idx++) {
    var r = data.rules[idx];
    html += '<div class="panel" style="margin-bottom:12px;">' +
      '<div class="panel-header" style="display:flex;align-items:center;gap:8px;">' +
      '<span style="color:' + DET_SC[r.severity] + ';font-weight:700;text-transform:uppercase;font-size:10px;">[' + r.severity + ']</span>' +
      '<span style="flex:1;">' + escHtml(r.name) + '</span>' +
      '<span style="font-size:10px;color:var(--purple);font-weight:700;">' + (DET_PN[r.platform] || r.platform) + '</span>' +
      '<button class="secondary" style="font-size:10px;padding:2px 7px;" onclick="copyDetectRule(' + idx + ',this)">Copy</button></div>' +
      '<div class="panel-body"><div style="font-size:11px;color:var(--text2);margin-bottom:8px;">' + escHtml(r.description) + '</div>';
    if (r.mitreAttack && r.mitreAttack.length) {
      html += '<div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:8px;">';
      for (var j = 0; j < r.mitreAttack.length; j++) html += '<span style="font-size:9px;padding:1px 6px;background:var(--bg3);border:1px solid var(--border);border-radius:2px;color:var(--accent);font-family:monospace;">' + r.mitreAttack[j] + '</span>';
      html += '</div>';
    }
    var ruleId = 'detect-rule-' + idx;
    html += '<details style="margin-bottom:8px;"><summary style="font-size:11px;color:var(--text);cursor:pointer;font-weight:600;">Rule Output</summary>' +
      '<pre id="' + ruleId + '" style="margin-top:6px;white-space:pre-wrap;font-size:11px;">' + escHtml(r.rule) + '</pre></details>';
    if (r.falsePositives && r.falsePositives.length) {
      html += '<details style="margin-bottom:8px;"><summary style="font-size:11px;color:var(--yellow);cursor:pointer;font-weight:600;">False Positives</summary><div style="padding:4px 0 4px 12px;">';
      for (var j = 0; j < r.falsePositives.length; j++) html += '<div style="font-size:11px;color:var(--text2);padding:2px 0;">• ' + escHtml(r.falsePositives[j]) + '</div>';
      html += '</div></details>';
    }
    if (r.tuningNotes && r.tuningNotes.length) {
      html += '<details><summary style="font-size:11px;color:var(--accent);cursor:pointer;font-weight:600;">Tuning Notes</summary><div style="padding:4px 0 4px 12px;">';
      for (var j = 0; j < r.tuningNotes.length; j++) html += '<div style="font-size:11px;color:var(--text2);padding:2px 0;">→ ' + escHtml(r.tuningNotes[j]) + '</div>';
      html += '</div></details>';
    }
    html += '</div></div>';
  }
  div.innerHTML = html;
}

function copyDetectRule(idx, btn) {
  var r = _detectRuleCache[idx];
  if (!r) return;
  copy(r.rule);
  if (btn) { btn.textContent = '✓ Copied'; setTimeout(function() { btn.textContent = 'Copy'; }, 1500); }
}

function copyAllDetectRules() {
  var all = '';
  for (var i = 0; i < _detectRuleCache.length; i++) {
    if (i > 0) all += '\n\n';
    all += '// [' + _detectRuleCache[i].platform.toUpperCase() + '] ' + _detectRuleCache[i].name + '\n' + _detectRuleCache[i].rule;
  }
  copy(all);
  showAlert('success', 'Copied ' + _detectRuleCache.length + ' rules');
}
