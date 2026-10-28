package query_log

// indexHTML is the entire web UI: one static page that polls /api/records
// and /api/upstreams and renders them as an upstream summary table plus a
// simple, collapsible timeline. No build step, no external dependencies,
// so it works fine on a NAS with no internet access.
//
// query_log: renderStep now recurses into st.children (see pkg/qtrace's
// Step.Children) so a concurrent branch's own steps (fallback's primary/
// secondary, dual_selector's reference_check/original_query) render as
// one nested block under that branch's marker row, instead of being
// flattened into the same list as everything else.
const indexHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mosdns 解析日志</title>
<style>
  :root {
    --ok: #2e7d32;
    --bad: #c62828;
    --warn: #ef6c00;
    --muted: #888;
    --bg: #fafafa;
    --line: #e2e2e2;
    --branch: #7b5fc7;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    padding: 16px;
    font-family: -apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
    background: var(--bg);
    color: #222;
  }
  h1 { font-size: 18px; margin: 0 0 12px; }
  h2 { font-size: 15px; margin: 18px 0 8px; }
  .toolbar { display:flex; align-items:center; gap:12px; margin-bottom:12px; font-size:13px; color:var(--muted); }
  .rec { background:#fff; border:1px solid var(--line); border-radius:6px; margin-bottom:6px; overflow:hidden; }
  .rec summary {
    cursor:pointer; padding:8px 12px; list-style:none;
    display:flex; gap:10px; align-items:center; font-size:13px;
  }
  .rec summary::-webkit-details-marker { display:none; }
  .rec summary .time { color:var(--muted); font-variant-numeric: tabular-nums; width:70px; flex-shrink:0; }
  .rec summary .qname { flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-weight:500; }
  .rec summary .qtype { color:var(--muted); width:44px; flex-shrink:0; }
  .rec summary .answer { color:var(--muted); flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .rec summary .rcode { font-weight:600; width:80px; flex-shrink:0; text-align:right; }
  .rec summary .elapsed { color:var(--muted); width:60px; text-align:right; flex-shrink:0; font-variant-numeric: tabular-nums; }
  .rcode-ok { color:var(--ok); }
  .rcode-bad { color:var(--bad); }
  .rcode-warn { color:var(--warn); }
  .steps { padding:4px 12px 10px 12px; border-top:1px solid var(--line); }
  .step { display:flex; gap:8px; align-items:baseline; padding:3px 0; font-size:12.5px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  .step .arrow { color:#bbb; }
  .step .seq { color:#7b5fc7; }
  .step .name { font-weight:600; }
  .step.skipped { color:#bbb; }
  .step .step-elapsed { color:var(--muted); margin-left:auto; flex-shrink:0; }
  .step.branch { border-left:2px solid var(--branch); padding-left:4px; margin-left:-6px; }
  .step.branch .name { color:var(--branch); }
  .empty { color:var(--muted); font-size:13px; padding:24px; text-align:center; }
  .upstreams { background:#fff; border:1px solid var(--line); border-radius:6px; overflow-x:auto; }
  .upstreams table { width:100%; border-collapse:collapse; font-size:13px; }
  .upstreams th, .upstreams td { padding:7px 12px; text-align:left; border-bottom:1px solid var(--line); white-space:nowrap; }
  .upstreams tr:last-child td { border-bottom:none; }
  .upstreams th { color:var(--muted); font-weight:500; background:#f4f4f4; }
  .upstreams td.num, .upstreams th.num { text-align:right; font-variant-numeric: tabular-nums; }
  .upstreams td.addr { color:var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12.5px; }
  .upstreams td.name { font-weight:600; }
</style>
</head>
<body>
  <h1>mosdns 解析日志</h1>
  <div class="toolbar">
    <label><input type="checkbox" id="autorefresh" checked> 自动刷新（2 秒）</label>
    <span id="count"></span>
  </div>

  <h2>上游服务器</h2>
  <div class="upstreams" id="upstreams"><div class="empty">加载中…</div></div>

  <h2>最近解析</h2>
  <div id="list"><div class="empty">加载中…</div></div>

<script>
function rcodeClass(rc) {
  if (rc === "NOERROR") return "rcode-ok";
  if (rc === "SERVFAIL" || rc === "REFUSED" || rc === "(no response)") return "rcode-bad";
  return "rcode-warn";
}
function esc(s) {
  return (s || "").replace(/[&<>"]/g, function(c) {
    return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c];
  });
}
function fmtTime(t) {
  var d = new Date(t);
  return d.toLocaleTimeString('zh-CN', {hour12:false});
}
// branchLevel counts how many levels of qtrace.Step.Children we have
// recursed into; it adds its own indent on top of the step's own
// "depth" field, purely for display, so a branch's nested steps are
// visibly indented under their branch marker.
function renderStep(st, branchLevel) {
  branchLevel = branchLevel || 0;
  var indent = 14 + st.depth * 16 + branchLevel * 16;
  var hasChildren = st.children && st.children.length > 0;
  var cls = "step" + (st.skipped ? " skipped" : "") + (hasChildren ? " branch" : "");
  var mid;
  if (st.skipped) {
    mid = "未命中，跳过";
  } else if (st.err) {
    mid = "错误：" + esc(st.err);
  } else if (st.rcode) {
    mid = '<span class="' + rcodeClass(st.rcode) + '">' + esc(st.rcode) +
          (st.answer ? " → " + esc(st.answer) : "") + '</span>';
  } else {
    mid = "已执行";
  }
  var seqLabel = st.seq ? '<span class="seq">' + esc(st.seq) + '</span><span class="arrow"> › </span>' : "";
  var html = '<div class="' + cls + '" style="padding-left:' + indent + 'px">' +
           seqLabel +
           '<span class="name">' + esc(st.name || st.kind) + '</span>' +
           '<span class="arrow">—</span>' +
           '<span>' + mid + '</span>' +
           '<span class="step-elapsed">' + st.elapsed_ms.toFixed(1) + 'ms</span>' +
         '</div>';
  if (hasChildren) {
    for (var i = 0; i < st.children.length; i++) {
      html += renderStep(st.children[i], branchLevel + 1);
    }
  }
  return html;
}
function renderRecord(r) {
  var rc = rcodeClass(r.rcode);
  var details = document.createElement('details');
  details.className = 'rec';
  var stepsHtml = (r.steps || []).map(function(st) { return renderStep(st, 0); }).join('');
  details.innerHTML =
    '<summary>' +
      '<span class="time">' + fmtTime(r.time) + '</span>' +
      '<span class="qname">' + esc(r.qname) + '</span>' +
      '<span class="qtype">' + esc(r.qtype) + '</span>' +
      '<span class="answer">' + esc(r.answer || '') + '</span>' +
      '<span class="rcode ' + rc + '">' + esc(r.rcode) + '</span>' +
      '<span class="elapsed">' + r.elapsed_ms.toFixed(1) + 'ms</span>' +
    '</summary>' +
    '<div class="steps">' + (stepsHtml || '<span style="color:#bbb">(无步骤记录)</span>') + '</div>';
  return details;
}
function renderUpstreams(list) {
  var box = document.getElementById('upstreams');
  if (!list || list.length === 0) {
    box.innerHTML = '<div class="empty">没有配置 forward 上游</div>';
    return;
  }
  var total = 0;
  var rows = '';
  for (var i = 0; i < list.length; i++) {
    var u = list[i];
    total += u.queries;
    var errCls = u.errors > 0 ? ' class="num rcode-bad"' : ' class="num"';
    rows += '<tr>' +
      '<td class="name">' + esc(u.name) + '</td>' +
      '<td class="addr">' + esc(u.addr) + '</td>' +
      '<td>' + (u.plugin ? esc(u.plugin) : '<span style="color:#bbb">(内联)</span>') + '</td>' +
      '<td class="num">' + u.queries + '</td>' +
      '<td' + errCls + '>' + u.errors + '</td>' +
    '</tr>';
  }
  box.innerHTML =
    '<table><thead><tr>' +
      '<th>上游</th><th>地址</th><th>所属插件</th>' +
      '<th class="num">查询次数</th><th class="num">失败次数</th>' +
    '</tr></thead><tbody>' + rows + '</tbody>' +
    '<tfoot><tr><td colspan="3" style="color:#888">合计</td>' +
      '<td class="num" style="font-weight:600">' + total + '</td><td></td></tr></tfoot></table>';
}
function refreshUpstreams() {
  fetch('/api/upstreams').then(function(res) { return res.json(); }).then(function(data) {
    renderUpstreams(data.upstreams || []);
  }).catch(function() { /* network hiccup, ignore this tick */ });
}
function refreshRecords() {
  fetch('/api/records?n=200').then(function(res) { return res.json(); }).then(function(data) {
    var list = document.getElementById('list');
    var openIds = {};
    list.querySelectorAll('details[open]').forEach(function(d) { openIds[d.dataset.id] = true; });
    list.innerHTML = '';
    var records = data.records || [];
    if (records.length === 0) {
      list.innerHTML = '<div class="empty">暂无解析记录</div>';
    } else {
      for (var i = 0; i < records.length; i++) {
        var r = records[i];
        var el = renderRecord(r);
        el.dataset.id = r.id;
        if (openIds[String(r.id)]) el.open = true;
        list.appendChild(el);
      }
    }
    document.getElementById('count').textContent = '最近 ' + records.length + ' 条';
  }).catch(function() { /* network hiccup, ignore this tick */ });
}
function refresh() {
  refreshUpstreams();
  refreshRecords();
}
refresh();
var timer = setInterval(refresh, 2000);
document.getElementById('autorefresh').addEventListener('change', function(e) {
  clearInterval(timer);
  if (e.target.checked) timer = setInterval(refresh, 2000);
});
</script>
</body>
</html>
`
