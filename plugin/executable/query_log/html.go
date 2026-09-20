package query_log

// indexHTML is the entire web UI: one static page that polls /api/records
// and renders it as a simple, collapsible timeline. No build step, no
// external dependencies, so it works fine on a NAS with no internet access.
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
  .empty { color:var(--muted); font-size:13px; padding:24px; text-align:center; }
</style>
</head>
<body>
  <h1>mosdns 解析日志</h1>
  <div class="toolbar">
    <label><input type="checkbox" id="autorefresh" checked> 自动刷新（2 秒）</label>
    <span id="count"></span>
  </div>
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
function renderStep(st) {
  var indent = 14 + st.depth * 16;
  var cls = st.skipped ? "step skipped" : "step";
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
  return '<div class="' + cls + '" style="padding-left:' + indent + 'px">' +
           seqLabel +
           '<span class="name">' + esc(st.name || st.kind) + '</span>' +
           '<span class="arrow">—</span>' +
           '<span>' + mid + '</span>' +
           '<span class="step-elapsed">' + st.elapsed_ms.toFixed(1) + 'ms</span>' +
         '</div>';
}
function renderRecord(r) {
  var rc = rcodeClass(r.rcode);
  var details = document.createElement('details');
  details.className = 'rec';
  var stepsHtml = (r.steps || []).map(renderStep).join('');
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
function refresh() {
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
