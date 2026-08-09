// ============================================================
// 实验对比页交互逻辑
// ============================================================

let charts = [];

document.addEventListener('DOMContentLoaded', async () => {
  try {
    const resp = await fetch('/api/experiment-results');
    const data = await resp.json();
    if (data.error) {
      document.getElementById('compareTableBody').innerHTML = `<tr><td colspan="10" class="alert alert-error">${data.error}</td></tr>`;
      return;
    }
    renderTable(data);
    renderAccF1Chart(data);
    renderRadarChart(data);
    renderLatencyChart(data);
  } catch (err) {
    document.getElementById('compareTableBody').innerHTML = `<tr><td colspan="10" class="alert alert-error">加载失败: ${err.message}</td></tr>`;
  }

  window.addEventListener('resize', () => charts.forEach(c => c && c.resize()));
});

// ---- 对比表格 ----
function renderTable(data) {
  const exps = data.experiments || {};
  const order = ['E1_zero_shot_ds', 'E2_few_shot_ds', 'E3_cot_ds', 'TS_ds', 'TS_qwen', 'E8_traditional'];
  const tbody = document.getElementById('compareTableBody');
  let html = '';

  for (const key of order) {
    const e = exps[key];
    if (!e) continue;
    const acc = (e.accuracy * 100).toFixed(1) + '%';
    const prec = (e.precision * 100).toFixed(1) + '%';
    const rec = (e.recall * 100).toFixed(1) + '%';
    const f1 = (e.f1 * 100).toFixed(1) + '%';
    const obfRec = (e.obfuscation_recall * 100).toFixed(1) + '%';
    const typeCons = (e.type_consistency * 100).toFixed(1) + '%';
    const latency = e.avg_latency_ms ? Math.round(e.avg_latency_ms) : 0;

    html += `<tr>
      <td style="text-align:left;font-weight:600;">${e.label}</td>
      <td>${acc}</td>
      <td>${prec}</td>
      <td>${rec}</td>
      <td>${f1}</td>
      <td>${obfRec}</td>
      <td>${typeCons}</td>
      <td>${e.fp}</td>
      <td>${e.fn}</td>
      <td>${latency}</td>
    </tr>`;
  }
  tbody.innerHTML = html;
}

// ---- 准确率/F1 柱状图 ----
function renderAccF1Chart(data) {
  const chart = echarts.init(document.getElementById('chartAccF1'));
  charts.push(chart);

  const exps = data.experiments || {};
  const order = ['E1_zero_shot_ds', 'E2_few_shot_ds', 'E3_cot_ds', 'TS_ds', 'TS_qwen', 'E8_traditional'];
  const labels = order.map(k => exps[k]?.label || k).filter(l => l);
  const accData = order.map(k => exps[k] ? +(exps[k].accuracy * 100).toFixed(1) : 0);
  const f1Data = order.map(k => exps[k] ? +(exps[k].f1 * 100).toFixed(1) : 0);

  chart.setOption({
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    legend: { data: ['准确率', 'F1'], top: 5 },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: { type: 'category', data: labels, axisLabel: { fontSize: 11, rotate: 15 } },
    yAxis: { type: 'value', min: 70, max: 105, axisLabel: { formatter: '{value}%' } },
    series: [
      { name: '准确率', type: 'bar', data: accData, itemStyle: { color: '#1d4ed8' }, label: { show: true, position: 'top', formatter: '{c}%', fontSize: 10 } },
      { name: 'F1', type: 'bar', data: f1Data, itemStyle: { color: '#dc2626' }, label: { show: true, position: 'top', formatter: '{c}%', fontSize: 10 } },
    ],
  });
}

// ---- 混淆识别率雷达图 ----
function renderRadarChart(data) {
  const chart = echarts.init(document.getElementById('chartRadar'));
  charts.push(chart);

  const exps = data.experiments || {};
  const order = ['E1_zero_shot_ds', 'E2_few_shot_ds', 'E3_cot_ds', 'TS_ds', 'TS_qwen', 'E8_traditional'];
  const obfTypes = ['base64', 'string_split', 'xor', 'comment_bypass'];
  const colors = ['#1d4ed8', '#059669', '#dc2626', '#f59e0b', '#8b5cf6', '#64748b'];

  const series = order.map((k, i) => {
    const e = exps[k];
    if (!e || !e.obf_by_type) return null;
    return {
      name: e.label,
      value: obfTypes.map(t => +(e.obf_by_type[t] * 100).toFixed(1)),
      lineStyle: { color: colors[i], width: 2 },
      itemStyle: { color: colors[i] },
      areaStyle: { opacity: 0.05 },
    };
  }).filter(Boolean);

  chart.setOption({
    tooltip: { trigger: 'item' },
    legend: { bottom: 5, left: 'center', textStyle: { fontSize: 10 } },
    radar: {
      indicator: obfTypes.map(t => ({ name: t, max: 100 })),
      shape: 'polygon', radius: '60%', center: ['50%', '45%'],
      axisName: { fontSize: 11 },
    },
    series: [{ type: 'radar', data: series }],
  });
}

// ---- 延迟对比 ----
function renderLatencyChart(data) {
  const chart = echarts.init(document.getElementById('chartLatency'));
  charts.push(chart);

  const exps = data.experiments || {};
  const order = ['E1_zero_shot_ds', 'E2_few_shot_ds', 'E3_cot_ds', 'TS_ds', 'TS_qwen', 'E8_traditional'];
  const labels = order.map(k => exps[k]?.label || k).filter(l => l);
  const latencies = order.map(k => exps[k] ? Math.round(exps[k].avg_latency_ms) : 0);

  chart.setOption({
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: { type: 'category', data: labels, axisLabel: { fontSize: 11, rotate: 15 } },
    yAxis: { type: 'value', name: '延迟(ms)' },
    series: [{
      type: 'bar', data: latencies, barWidth: '45%',
      itemStyle: { color: function(p) { return ['#1d4ed8','#1d4ed8','#dc2626','#1d4ed8','#8b5cf6','#64748b'][p.dataIndex] || '#1d4ed8'; }, borderRadius: [4, 4, 0, 0] },
      label: { show: true, position: 'top', fontSize: 10 },
    }],
  });
}
