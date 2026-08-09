// ============================================================
// 数据看板页交互逻辑
// ============================================================

let charts = [];

document.addEventListener('DOMContentLoaded', async () => {
  try {
    const resp = await fetch('/api/dataset-stats');
    const data = await resp.json();
    if (data.error) {
      document.querySelector('.stat-grid').innerHTML = `<div class="alert alert-error">${data.error}</div>`;
      return;
    }
    renderStats(data);
    renderCategoryChart(data);
    renderLanguageChart(data);
    renderObfuscationChart(data);
    renderBenignSourceChart(data);
  } catch (err) {
    document.querySelector('.stat-grid').innerHTML = `<div class="alert alert-error">加载失败: ${err.message}</div>`;
  }

  window.addEventListener('resize', () => charts.forEach(c => c && c.resize()));
});

// ---- 统计卡片 ----
function renderStats(data) {
  document.getElementById('statTotal').textContent = data.total;
  document.getElementById('statBenign').textContent = data.by_label?.benign || 0;
  document.getElementById('statMalicious').textContent = data.by_label?.malicious || 0;
  document.getElementById('statObfuscated').textContent = data.by_category?.obfuscated || 0;
}

// ---- 样本分类饼图 ----
function renderCategoryChart(data) {
  const chart = echarts.init(document.getElementById('chartCategory'));
  charts.push(chart);

  const cat = data.by_category || {};
  chart.setOption({
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    legend: { bottom: 5, left: 'center', textStyle: { fontSize: 12 } },
    series: [{
      type: 'pie', radius: ['35%', '60%'], center: ['50%', '45%'],
      data: [
        { value: cat.benign || 0, name: '良性', itemStyle: { color: '#059669' } },
        { value: cat.webshell || 0, name: 'WebShell', itemStyle: { color: '#dc2626' } },
        { value: cat.sqli || 0, name: 'SQLi', itemStyle: { color: '#f59e0b' } },
        { value: cat.obfuscated || 0, name: '混淆变种', itemStyle: { color: '#8b5cf6' } },
      ],
      label: { formatter: '{b}\n{c}', fontSize: 11 },
    }],
  });
}

// ---- 语言分布柱状图 ----
function renderLanguageChart(data) {
  const chart = echarts.init(document.getElementById('chartLanguage'));
  charts.push(chart);

  const lang = data.by_language || {};
  const entries = Object.entries(lang).sort((a, b) => b[1] - a[1]);
  const names = entries.map(e => e[0]);
  const values = entries.map(e => e[1]);

  chart.setOption({
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: { type: 'category', data: names, axisLabel: { fontSize: 11 } },
    yAxis: { type: 'value', name: '样本数' },
    series: [{
      type: 'bar', data: values, barWidth: '50%',
      itemStyle: { color: '#1d4ed8', borderRadius: [4, 4, 0, 0] },
      label: { show: true, position: 'top', fontSize: 11 },
    }],
  });
}

// ---- 混淆类型分布 ----
function renderObfuscationChart(data) {
  const chart = echarts.init(document.getElementById('chartObfuscation'));
  charts.push(chart);

  const obf = data.by_obfuscation || {};
  const names = Object.keys(obf);
  const values = Object.values(obf);
  const colors = ['#8b5cf6', '#06b6d4', '#f59e0b', '#ec4899'];

  chart.setOption({
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    legend: { bottom: 5, left: 'center', textStyle: { fontSize: 11 } },
    series: [{
      type: 'pie', radius: '55%', center: ['50%', '45%'],
      data: names.map((n, i) => ({ value: values[i], name: n, itemStyle: { color: colors[i % colors.length] } })),
      label: { formatter: '{b}\n{c}', fontSize: 11 },
    }],
  });
}

// ---- 良性样本来源 ----
function renderBenignSourceChart(data) {
  const chart = echarts.init(document.getElementById('chartBenignSource'));
  charts.push(chart);

  const src = data.benign_sources || {};
  const entries = Object.entries(src).sort((a, b) => b[1] - a[1]);
  const names = entries.map(e => e[0]);
  const values = entries.map(e => e[1]);

  chart.setOption({
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: { type: 'category', data: names, axisLabel: { fontSize: 11 } },
    yAxis: { type: 'value', name: '样本数' },
    series: [{
      type: 'bar', data: values, barWidth: '40%',
      itemStyle: { color: '#059669', borderRadius: [4, 4, 0, 0] },
      label: { show: true, position: 'top', fontSize: 11 },
    }],
  });
}
