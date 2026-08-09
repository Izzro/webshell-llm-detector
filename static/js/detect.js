// ============================================================
// 在线检测页交互逻辑
// ============================================================

// ---- 加载示例代码（从后端API获取，避免JS文件含恶意模式）----
async function loadExample(type) {
  try {
    var resp = await fetch('/api/example?type=' + type);
    var data = await resp.json();
    if (data.code) {
      document.getElementById('codeInput').value = data.code;
    }
  } catch(e) {
    console.error('Failed to load example:', e);
  }
}

// ---- 清空输入 ----
function clearCode() {
  document.getElementById('codeInput').value = '';
  document.getElementById('resultArea').innerHTML = ''
    + '<div class="card" style="text-align:center; color:var(--muted); padding:3rem;">'
    + '<p style="font-size:0.9rem;">\u68C0\u6D4B\u7ED3\u679C\u5C06\u5728\u6B64\u663E\u793A</p>'
    + '<p style="font-size:0.8rem; margin-top:0.5rem;">\u70B9\u51FB\u201C\u5F00\u59CB\u68C0\u6D4B\u201D\u6309\u94AE</p>'
    + '</div>';
}

// ---- 文件上传 ----
function handleFile(event) {
  var file = event.target.files[0];
  if (!file) return;
  var reader = new FileReader();
  reader.onload = function(e) {
    document.getElementById('codeInput').value = e.target.result;
  };
  reader.readAsText(file);
}

// ---- 提交检测 ----
async function runDetect() {
  var codeText = document.getElementById('codeInput').value.trim();
  if (!codeText) {
    alert('\u8BF7\u8F93\u5165\u4EE3\u7801\u5185\u5BB9');
    return;
  }
  var provider = document.getElementById('provider').value;
  var strategy = document.getElementById('strategy').value;
  var language = document.getElementById('language').value;
  var btn = document.getElementById('detectBtn');
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner" style="width:16px;height:16px;border-width:2px;"></div> \u68C0\u6D4B\u4E2D...';
  document.getElementById('resultArea').innerHTML = ''
    + '<div class="card loading"><div class="spinner"></div>\u6B63\u5728\u8C03\u7528 LLM \u68C0\u6D4B\uFF0C\u8BF7\u7A0D\u5019...</div>';
  try {
    var resp = await fetch('/api/detect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code_text: codeText, provider: provider, strategy: strategy, language: language }),
    });
    var data = await resp.json();
    if (data.error) {
      renderError(data);
    } else {
      renderResults(data);
    }
  } catch (err) {
    document.getElementById('resultArea').innerHTML = ''
      + '<div class="alert alert-error">\u8BF7\u6C42\u5931\u8D25: ' + err.message + '</div>';
  } finally {
    btn.disabled = false;
    btn.innerHTML = '\uD83D\uDD0D \u5F00\u59CB\u68C0\u6D4B';
  }
}

// ---- 渲染结果 ----
function renderResults(data) {
  var llm = data.llm || {};
  var trad = data.traditional || {};
  var usage = data.usage || {};
  var lang = data.language || 'unknown';
  var llmLabel = llm.label || 'unknown';
  var llmIsMal = llmLabel === 'malicious';
  var tradLabel = trad.label || 'unknown';
  var tradIsMal = tradLabel === 'malicious';
  var llmConf = llm.confidence || 0;
  var confClass = llmConf >= 0.85 ? 'high' : (llmConf >= 0.6 ? 'mid' : 'low');
  var confPct = Math.round(llmConf * 100);
  var latency = usage.latency_ms ? Math.round(usage.latency_ms) : 0;
  var tokens = usage.total_tokens || 0;
  var providerVal = usage.provider || document.getElementById('provider').value;
  var strategyVal = usage.strategy || document.getElementById('strategy').value;
  var indicatorsHtml = '';
  if (llm.indicators && llm.indicators.length) {
    indicatorsHtml = '<div class="result-reason"><strong>\u6076\u610F\u6307\u6807\uFF1A</strong><ul style="margin:0.3rem 0 0 1.2rem;">';
    llm.indicators.forEach(function(i) {
      indicatorsHtml += '<li style="font-size:0.82rem;">' + i + '</li>';
    });
    indicatorsHtml += '</ul></div>';
  }
  var rulesHtml = '';
  if (trad.rules_triggered && trad.rules_triggered.length) {
    rulesHtml = '<div class="result-reason"><strong>\u89E6\u53D1\u89C4\u5219 (' + trad.rules_triggered.length + '\u6761)\uFF1A</strong>'
      + '<code style="display:block;margin-top:0.3rem;font-size:0.78rem;">' + trad.rules_triggered.slice(0, 5).join(' \u00B7 ') + '</code></div>';
  }
  var html = '';
  // LLM \u7ED3\u679C
  html += '<div class="card result-section">';
  html += '<div class="card-title">LLM \u68C0\u6D4B\u7ED3\u679C (' + (usage.model || providerVal) + ')</div>';
  var llmHeaderClass = llmIsMal ? 'malicious' : (llmLabel === 'benign' ? 'benign' : 'unknown');
  var llmIcon = llmIsMal ? '\uD83D\uDD34 \u6076\u610F' : (llmLabel === 'benign' ? '\uD83D\uDFE2 \u826F\u6027' : '\u26AA \u672A\u77E5');
  html += '<div class="result-header ' + llmHeaderClass + '">';
  html += '<span>' + llmIcon + '</span>';
  html += '<span>\u7F6E\u4FE1\u5EA6 ' + confPct + '%</span>';
  html += '</div>';
  html += '<div class="confidence-bar"><div class="fill ' + confClass + '" style="width:' + confPct + '%"></div></div>';
  html += '<div class="result-grid" style="margin-top:0.75rem;">';
  html += '<div class="result-item"><div class="label">\u6076\u610F\u7C7B\u578B</div><div class="value">' + (llm.malware_type || '\u2014') + '</div></div>';
  html += '<div class="result-item"><div class="label">\u5B50\u7C7B\u578B</div><div class="value">' + (llm.subtype || '\u2014') + '</div></div>';
  html += '<div class="result-item"><div class="label">\u6DF7\u6DC6\u65B9\u5F0F</div><div class="value">' + (llm.obfuscation || '\u65E0') + '</div></div>';
  html += '<div class="result-item"><div class="label">\u98CE\u9669\u7B49\u7EA7</div><div class="value">' + (llm.risk_level || '\u2014') + '</div></div>';
  html += '</div>';
  if (llm.reason) {
    html += '<div class="result-reason"><strong>\u5206\u6790\uFF1A</strong>' + llm.reason + '</div>';
  }
  html += indicatorsHtml;
  if (llm.parse_error) {
    html += '<div class="alert alert-error">\u89E3\u6790\u8B66\u544A: ' + llm.parse_error + '</div>';
  }
  html += '</div>';
  // \u4F20\u7EDF\u626B\u63CF\u5668\u7ED3\u679C
  html += '<div class="card result-section">';
  html += '<div class="card-title">\u4F20\u7EDF\u626B\u63CF\u5668\u5BF9\u7167\u7ED3\u679C</div>';
  var tradHeaderClass = tradIsMal ? 'malicious' : (tradLabel === 'benign' ? 'benign' : 'unknown');
  var tradIcon = tradIsMal ? '\uD83D\uDD34 \u6076\u610F' : (tradLabel === 'benign' ? '\uD83D\uDFE2 \u826F\u6027' : '\u26AA \u672A\u77E5');
  html += '<div class="result-header ' + tradHeaderClass + '">';
  html += '<span>' + tradIcon + '</span>';
  html += '<span>\u7F6E\u4FE1\u5EA6 ' + Math.round((trad.confidence || 0) * 100) + '%</span>';
  html += '</div>';
  html += '<div class="result-grid" style="margin-top:0.5rem;">';
  html += '<div class="result-item"><div class="label">\u6076\u610F\u7C7B\u578B</div><div class="value">' + (trad.malware_type || '\u2014') + '</div></div>';
  html += '<div class="result-item"><div class="label">\u5B50\u7C7B\u578B</div><div class="value">' + (trad.subtype || '\u2014') + '</div></div>';
  html += '<div class="result-item"><div class="label">\u6DF7\u6DC6\u65B9\u5F0F</div><div class="value">' + (trad.obfuscation || '\u65E0') + '</div></div>';
  html += '<div class="result-item"><div class="label">\u98CE\u9669\u7B49\u7EA7</div><div class="value">' + (trad.risk_level || '\u2014') + '</div></div>';
  html += '</div>';
  if (trad.reason) {
    html += '<div class="result-reason"><strong>\u5206\u6790\uFF1A</strong>' + trad.reason + '</div>';
  }
  html += rulesHtml;
  html += '</div>';
  // \u5143\u4FE1\u606F
  html += '<div class="card" style="padding:0.75rem 1rem;">';
  html += '<div style="display:flex; gap:1.5rem; flex-wrap:wrap; font-size:0.8rem; color:var(--muted);">';
  html += '<span>\u8BED\u8A00: <strong style="color:var(--ink)">' + lang + '</strong></span>';
  html += '<span>\u7B56\u7565: <strong style="color:var(--ink)">' + strategyVal + '</strong></span>';
  html += '<span>\u5EF6\u8FDF: <strong style="color:var(--ink)">' + latency + 'ms</strong></span>';
  html += '<span>Tokens: <strong style="color:var(--ink)">' + tokens.toLocaleString() + '</strong></span>';
  html += '</div></div>';
  document.getElementById('resultArea').innerHTML = html;
}

// ---- \u6E32\u67D3\u9519\u8BEF ----
function renderError(data) {
  var trad = data.traditional || {};
  var tradLabel = trad.label || 'unknown';
  var tradIsMal = tradLabel === 'malicious';
  var html = '<div class="alert alert-error">' + data.error + '</div>';
  if (trad.label) {
    html += '<div class="card result-section">';
    html += '<div class="card-title">\u4F20\u7EDF\u626B\u63CF\u5668\u7ED3\u679C\uFF08LLM \u8C03\u7528\u5931\u8D25\u65F6\u4ECD\u53EF\u7528\uFF09</div>';
    html += '<div class="result-header ' + (tradIsMal ? 'malicious' : 'benign') + '">';
    html += '<span>' + (tradIsMal ? '\uD83D\uDD34 \u6076\u610F' : '\uD83D\uDFE2 \u826F\u6027') + '</span>';
    html += '<span>\u7F6E\u4FE1\u5EA6 ' + Math.round((trad.confidence || 0) * 100) + '%</span>';
    html += '</div>';
    if (trad.reason) {
      html += '<div class="result-reason"><strong>\u5206\u6790\uFF1A</strong>' + trad.reason + '</div>';
    }
    html += '</div>';
  }
  document.getElementById('resultArea').innerHTML = html;
}
