package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// The panel UI is a couple of small self-contained pages. All dynamic data
// (backend names, upstream addresses, error strings) is fetched from the JSON
// API and rendered client-side with textContent / DOM nodes only — never
// innerHTML — so it cannot inject markup, and a strict nonce-based CSP blocks
// anything the escaping might miss. The only values templated into the HTML
// here are the per-response nonce and a small JSON config object of
// server-generated, validated strings.

const panelCSS = `
:root{color-scheme:dark light}
*{box-sizing:border-box}
body{margin:0;font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
background:#0e1116;color:#e6edf3}
a{color:#58a6ff}
header{display:flex;align-items:center;gap:12px;padding:14px 18px;border-bottom:1px solid #222c38;
background:#161b22;position:sticky;top:0}
header h1{font-size:16px;margin:0;font-weight:600}
header .sp{flex:1}
header .who{color:#8b949e;font-size:13px}
main{max-width:1100px;margin:0 auto;padding:18px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:18px}
.card{background:#161b22;border:1px solid #222c38;border-radius:8px;padding:12px 14px}
.card .k{color:#8b949e;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.card .v{font-size:22px;font-weight:600;margin-top:4px;word-break:break-word}
.card .s{color:#8b949e;font-size:12px;margin-top:2px}
h2{font-size:14px;color:#8b949e;text-transform:uppercase;letter-spacing:.04em;margin:22px 0 8px}
table{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #222c38;border-radius:8px;overflow:hidden}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid #222c38;font-size:13px;vertical-align:top}
th{color:#8b949e;font-weight:600;background:#11161d}
tr:last-child td{border-bottom:none}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600}
.up{background:#13331f;color:#3fb950}
.down{background:#3d1416;color:#f85149}
.off{background:#2b2f36;color:#8b949e}
.btn{font:inherit;cursor:pointer;border:1px solid #30363d;background:#21262d;color:#e6edf3;
border-radius:6px;padding:5px 10px}
.btn:hover{background:#30363d}
.btn.danger{border-color:#5c1f22}
.btn.primary{background:#1f6feb;border-color:#1f6feb;color:#fff}
.muted{color:#8b949e}
.err{background:#3d1416;color:#f85149;border:1px solid #5c1f22;border-radius:6px;padding:8px 12px;margin-bottom:12px}
.ok{background:#13331f;color:#3fb950;border:1px solid #1c5531;border-radius:6px;padding:8px 12px;margin-bottom:12px}
.login{max-width:320px;margin:12vh auto;background:#161b22;border:1px solid #222c38;border-radius:10px;padding:22px}
.login h1{font-size:18px;margin:0 0 4px}
.login p{color:#8b949e;margin:0 0 16px;font-size:13px}
.login label{display:block;font-size:12px;color:#8b949e;margin:10px 0 4px}
.login input{width:100%;padding:9px 10px;border-radius:6px;border:1px solid #30363d;background:#0e1116;color:#e6edf3;font:inherit}
.login button{width:100%;margin-top:16px;padding:10px}
.foot{color:#586069;font-size:12px;margin-top:18px;text-align:center}
.bar{display:flex;align-items:center;gap:8px;margin:18px 0 4px;flex-wrap:wrap}
.bar h2{margin:0;flex:1}
form.add{background:#11161d;border:1px solid #222c38;border-radius:8px;padding:10px 12px;margin:4px 0 8px;
display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end}
form.add .f{display:flex;flex-direction:column;gap:3px}
form.add label{font-size:11px;color:#8b949e}
form.add input,form.add select{padding:6px 8px;border-radius:6px;border:1px solid #30363d;background:#0e1116;color:#e6edf3;font:inherit}
form.add input[type=text]{min-width:140px}
.hint{color:#8b949e;font-size:12px;margin:0 0 8px}
.act{display:flex;gap:6px;white-space:nowrap}
.btn.sm{padding:3px 8px;font-size:12px}
.rate{font-variant-numeric:tabular-nums}
.x{cursor:pointer;color:#f85149;border:none;background:none;font-size:15px;padding:0 4px}
`

func writePanelLogin(w http.ResponseWriter, nonce, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	writePanelLoginBody(w, nonce, errMsg)
}

func writePanelLoginBody(w http.ResponseWriter, nonce, errMsg string) {
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	var errBlock string
	if errMsg != "" {
		errBlock = `<div class="err">` + htmlEscape(errMsg) + `</div>`
	}
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	b.WriteString(`<meta name="robots" content="noindex,nofollow">`)
	b.WriteString(`<title>Sign in</title><style nonce="` + nonce + `">` + panelCSS + `</style></head><body>`)
	b.WriteString(`<form class="login" method="post" action="login" autocomplete="off">`)
	b.WriteString(`<h1>ayana-cdn</h1><p>Sign in to the control panel.</p>`)
	b.WriteString(errBlock)
	b.WriteString(`<label for="u">Username</label><input id="u" name="username" autocomplete="username" autofocus>`)
	b.WriteString(`<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password">`)
	b.WriteString(`<button class="btn primary" type="submit">Sign in</button>`)
	b.WriteString(`</form><div class="foot">authorized access only</div></body></html>`)
	_, _ = w.Write([]byte(b.String()))
}

type dashData struct {
	Base    string `json:"base"`
	User    string `json:"user"`
	CSRF    string `json:"csrf"`
	Control bool   `json:"control"`
}

func writePanelDashboard(w http.ResponseWriter, nonce string, d dashData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	cfgJSON, _ := json.Marshal(d) // json.Marshal escapes <,>,& — safe inside <script>

	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	b.WriteString(`<meta name="robots" content="noindex,nofollow">`)
	b.WriteString(`<title>ayana-cdn panel</title><style nonce="` + nonce + `">` + panelCSS + `</style></head><body>`)
	b.WriteString(`<header><h1>ayana-cdn</h1><span class="pill off" id="mode">&nbsp;</span><span class="sp"></span>`)
	b.WriteString(`<span class="who" id="who"></span>`)
	b.WriteString(`<form method="post" action="logout" style="margin:0" id="logoutForm">`)
	b.WriteString(`<input type="hidden" name="csrf" id="csrfField">`)
	b.WriteString(`<button class="btn" type="submit">Sign out</button></form></header>`)
	b.WriteString(`<main><div id="msg"></div><div class="cards" id="cards"></div>`)
	b.WriteString(`<div id="controls"></div>`)
	b.WriteString(`<div class="bar"><h2>Domains</h2><span id="domainCtl"></span></div>`)
	b.WriteString(`<div id="domainForm"></div><div id="domains"></div>`)
	b.WriteString(`<div class="bar"><h2>Backends &amp; paths</h2><span id="backendCtl"></span></div>`)
	b.WriteString(`<div id="backendForm"></div><div id="backends"></div>`)
	b.WriteString(`<div class="bar"><h2>Client IPs</h2><span id="ipCtl"></span></div>`)
	b.WriteString(`<div id="ipNote" class="hint"></div><div id="iplog"></div>`)
	b.WriteString(`<h2>Runtime</h2><div class="cards" id="runtime"></div>`)
	b.WriteString(`<div class="foot muted" id="updated"></div></main>`)
	b.WriteString(`<noscript><p class="muted" style="padding:18px">JavaScript is required. The raw status is at <a href="api/status">api/status</a>.</p></noscript>`)
	b.WriteString(`<script nonce="` + nonce + `">var APP=` + string(cfgJSON) + `;</script>`)
	b.WriteString(`<script nonce="` + nonce + `">` + panelJS + `</script>`)
	b.WriteString(`</body></html>`)
	_, _ = w.Write([]byte(b.String()))
}

// htmlEscape is used only for the fixed login error strings.
func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}

const panelJS = `
"use strict";
var $ = function(id){return document.getElementById(id)};
function el(tag,txt,cls){var e=document.createElement(tag);if(txt!=null)e.textContent=txt;if(cls)e.className=cls;return e}
function card(parent,k,v,s){var c=el("div",null,"card");c.appendChild(el("div",k,"k"));c.appendChild(el("div",String(v),"v"));if(s!=null)c.appendChild(el("div",String(s),"s"));parent.appendChild(c)}
function bytes(n){n=Number(n)||0;var u=["B","KiB","MiB","GiB","TiB","PiB"],i=0;while(n>=1024&&i<u.length-1){n/=1024;i++}return (i?n.toFixed(1):Math.round(n))+u[i]}
function dur(sec){sec=Number(sec)||0;if(sec>=86400)return Math.floor(sec/86400)+"d"+Math.floor((sec%86400)/3600)+"h";if(sec>=3600)return Math.floor(sec/3600)+"h"+Math.floor((sec%3600)/60)+"m";if(sec>=60)return Math.floor(sec/60)+"m"+(sec%60)+"s";return sec+"s"}
$("csrfField").value=APP.csrf;

// Live rates from byte deltas between polls, shown in Mbps (megabits/sec,
// decimal — the usual network throughput unit).
var prev={t:0,b:{},h:{}};
var ipSel=null; // selected backend for the Client IPs section
function mbps(bytesPerSec){var v=bytesPerSec*8/1e6;return (v<10?v.toFixed(2):v.toFixed(1))+" Mbps"}
function rate(curUp,curDown,key,bucket){
  var dt=(Date.now()-prev.t)/1000, p=prev[bucket][key];
  var s="–";
  if(p&&dt>0.5){s=mbps((curUp-p.u)/dt)+" ↑  "+mbps((curDown-p.d)/dt)+" ↓"}
  return s;
}

function post(path,params,done){
  var body=Object.keys(params).map(function(k){return encodeURIComponent(k)+"="+encodeURIComponent(params[k])}).join("&");
  fetch(APP.base+path,{method:"POST",credentials:"same-origin",
    headers:{"X-CSRF-Token":APP.csrf,"Content-Type":"application/x-www-form-urlencoded"},body:body})
  .then(function(r){return r.json().catch(function(){return{ok:false,error:"HTTP "+r.status}})})
  .then(function(j){done(j)}).catch(function(e){done({ok:false,error:String(e)})});
}
function flash(msg,ok){var m=$("msg");m.innerHTML="";var d=el("div",msg,ok?"ok":"err");m.appendChild(d);setTimeout(function(){if(m.firstChild===d)m.innerHTML=""},7000)}

function field(label,node){var f=el("div",null,"f");f.appendChild(el("label",label));f.appendChild(node);return f}
function sel(opts,val){var s=document.createElement("select");opts.forEach(function(o){var op=document.createElement("option");op.value=o;op.textContent=o;if(o===val)op.selected=true;s.appendChild(op)});return s}
function inp(ph,val){var i=document.createElement("input");i.type="text";i.placeholder=ph||"";if(val!=null)i.value=val;return i}

function renderControls(){
  var c=$("controls");c.innerHTML="";
  if(!APP.control){ $("domainCtl").textContent=""; $("backendCtl").textContent=""; return; }
  var b=el("button","Reload config","btn sm");
  b.addEventListener("click",function(){b.disabled=true;post("/api/reload",{},function(j){b.disabled=false;flash(j.ok?j.message:("reload: "+j.error),j.ok);load()})});
  c.appendChild(b);
  if(!$("domainCtl").firstChild){
    var ad=el("button","+ Add domain","btn sm");ad.addEventListener("click",domainForm);$("domainCtl").appendChild(ad);
    var ab=el("button","+ Add backend / path","btn sm");ab.addEventListener("click",function(){backendForm(null)});$("backendCtl").appendChild(ab);
  }
}

function domainForm(){
  var wrap=$("domainForm");wrap.innerHTML="";
  var f=document.createElement("form");f.className="add";
  var host=inp("sub.example.com");
  f.appendChild(field("New domain (must resolve to this server)",host));
  var save=el("button","Add","btn primary sm");save.type="submit";
  var cancel=el("button","Cancel","btn sm");cancel.type="button";cancel.addEventListener("click",function(){wrap.innerHTML=""});
  f.appendChild(field(" ",save));f.appendChild(field(" ",cancel));
  f.addEventListener("submit",function(e){e.preventDefault();post("/api/host",{action:"add",host:host.value},function(j){flash(j.ok?j.message:("error: "+j.error),j.ok);if(j.ok)wrap.innerHTML="";load()})});
  wrap.appendChild(f);host.focus();
}

function backendForm(bk){
  var wrap=$("backendForm");wrap.innerHTML="";
  var editing=!!bk;
  var f=document.createElement("form");f.className="add";
  var name=inp("path (e.g. native1 or app)",editing?bk.name:"");if(editing)name.disabled=true;
  var proto=sel(["wss","ws","https","http","sse","udp"],editing?bk.proto:"wss");
  var ups=inp("host:port, host:port",editing?(bk.upstreams||[]).map(function(u){return u.addr}).join(", "):"");
  var host=inp("Host header (optional)",editing?(bk.host||""):"");
  var listen=inp(":36712 (udp only)",editing?(bk.listen||""):"");
  var strip=sel(["true","false"],editing?String(bk.strip):"true");
  var relay=sel(["upgrade","always"],editing?(bk.relay||"upgrade"):"upgrade");
  var lb=sel(["least_conn","round_robin","first","hash"],editing?(bk.lb||"least_conn"):"least_conn");
  var insecure=sel(["false","true"],editing?String(bk.insecure):"false");
  f.appendChild(field("Path name",name));
  f.appendChild(field("Proto",proto));
  f.appendChild(field("Upstreams",ups));
  f.appendChild(field("Host",host));
  f.appendChild(field("Listen (udp)",listen));
  f.appendChild(field("Strip path",strip));
  f.appendChild(field("Relay",relay));
  f.appendChild(field("LB",lb));
  f.appendChild(field("Insecure TLS",insecure));
  var save=el("button",editing?"Save":"Add","btn primary sm");save.type="submit";
  var cancel=el("button","Cancel","btn sm");cancel.type="button";cancel.addEventListener("click",function(){wrap.innerHTML=""});
  f.appendChild(field(" ",save));f.appendChild(field(" ",cancel));
  var hint=el("div","Local service on this VPS: set Proto = http (or https) and Upstreams = 127.0.0.1:PORT. Tunnels: wss/ws. Clients reach it at /"+(editing?bk.name:"<name>")+"/.","hint");
  f.addEventListener("submit",function(e){e.preventDefault();
    post("/api/backend",{action:editing?"update":"add",name:name.value,proto:proto.value,upstreams:ups.value,
      host:host.value,listen:listen.value,strip:strip.value,relay:relay.value,lb:lb.value,insecure:insecure.value},
      function(j){flash(j.ok?j.message:("error: "+j.error),j.ok);if(j.ok)wrap.innerHTML="";load()});
  });
  wrap.appendChild(f);wrap.appendChild(hint);name.focus();
}

function hostToggle(action,host){post("/api/host",{action:action,host:host},function(j){flash(j.ok?j.message:("error: "+j.error),j.ok);load()})}
function backendAction(action,name){post("/api/backend",{action:action,name:name},function(j){flash(j.ok?j.message:("error: "+j.error),j.ok);load()})}

function renderDomains(d){
  var wrap=$("domains");wrap.innerHTML="";
  var t=el("table"),h=el("tr");
  var cols=["Domain","Requests","Active","Rate (Mbps)","Total up/down"];if(APP.control)cols.push("");
  cols.forEach(function(c){h.appendChild(el("th",c))});t.appendChild(h);
  (d.host_traffic||[]).forEach(function(ht){
    var tr=el("tr");
    tr.appendChild(el("td",ht.host));
    tr.appendChild(el("td",ht.requests||0));
    tr.appendChild(el("td",ht.active||0));
    tr.appendChild(el("td",rate(ht.bytes_up,ht.bytes_down,ht.host,"h"),"rate"));
    tr.appendChild(el("td",bytes(ht.bytes_up)+" / "+bytes(ht.bytes_down)));
    if(APP.control){var td=el("td");if(ht.host!=="other"){var x=el("button","×","x");x.title="remove domain";(function(hn){x.addEventListener("click",function(){if(confirm("Remove domain "+hn+"?"))hostToggle("remove",hn)})})(ht.host);td.appendChild(x);}tr.appendChild(td);}
    t.appendChild(tr);
    prev.h[ht.host]={u:ht.bytes_up,d:ht.bytes_down};
  });
  wrap.appendChild(t);
}

function renderBackends(d){
  var wrap=$("backends");wrap.innerHTML="";
  var t=el("table"),h=el("tr");
  var cols=["Backend","Path","Proto","Open","Total","Failed","Rate (Mbps)","Upstreams"];if(APP.control)cols.push("Actions");
  cols.forEach(function(c){h.appendChild(el("th",c))});t.appendChild(h);
  (d.backends||[]).forEach(function(b){
    var tr=el("tr");
    var nameTd=el("td");nameTd.appendChild(el("span",b.name));
    if(b.disabled){nameTd.appendChild(document.createTextNode(" "));nameTd.appendChild(el("span","disabled","pill off"))}
    tr.appendChild(nameTd);
    tr.appendChild(el("td",b.listen?("udp "+b.listen):b.path));
    tr.appendChild(el("td",b.proto+(b.relay==="always"?" raw":"")));
    tr.appendChild(el("td",b.tunnels_active));
    tr.appendChild(el("td",b.tunnels_total));
    tr.appendChild(el("td",b.failures));
    tr.appendChild(el("td",rate(b.bytes_up,b.bytes_down,b.name,"b"),"rate"));
    var upsTd=el("td");
    (b.upstreams||[]).forEach(function(u){
      var p=el("div");p.appendChild(el("span",u.addr+" "));
      p.appendChild(el("span",u.healthy?"up":"down",u.healthy?"pill up":"pill down"));
      if(u.active)p.appendChild(document.createTextNode(" "+u.active));
      upsTd.appendChild(p);if(!u.healthy&&u.last_error)upsTd.appendChild(el("div",u.last_error,"muted"));
    });
    tr.appendChild(upsTd);
    if(APP.control){
      var act=el("td",null,"act");
      var tg=el("button",b.disabled?"Enable":"Disable","btn sm"+(b.disabled?"":" danger"));
      (function(n,dis){tg.addEventListener("click",function(){backendAction(dis?"enable":"disable",n)})})(b.name,b.disabled);
      var ed=el("button","Edit","btn sm");(function(bb){ed.addEventListener("click",function(){backendForm(bb)})})(b);
      var rm=el("button","Remove","btn sm");(function(n){rm.addEventListener("click",function(){if(confirm("Remove backend "+n+"?"))backendAction("remove",n)})})(b.name);
      act.appendChild(tg);act.appendChild(ed);act.appendChild(rm);tr.appendChild(act);
    }
    t.appendChild(tr);
    prev.b[b.name]={u:b.bytes_up,d:b.bytes_down};
  });
  wrap.appendChild(t);
}

function renderIPSection(d){
  var ctl=$("ipCtl");
  var names=(d.backends||[]).map(function(b){return b.name});
  var sel=$("ipBackend");
  if(!sel){sel=document.createElement("select");sel.id="ipBackend";sel.addEventListener("change",function(){ipSel=sel.value;loadIPLog()});ctl.appendChild(sel);}
  var want=names.join("\u0001");
  if(sel.getAttribute("data-k")!==want){
    sel.innerHTML="";names.forEach(function(n){var o=document.createElement("option");o.value=n;o.textContent=n;sel.appendChild(o)});
    sel.setAttribute("data-k",want);
  }
  if(!ipSel||names.indexOf(ipSel)<0)ipSel=names[0]||null;
  if(ipSel)sel.value=ipSel;
  loadIPLog();
}
function loadIPLog(){
  if(!ipSel){$("iplog").innerHTML="";$("ipNote").textContent="";return;}
  fetch(APP.base+"/api/iplog?backend="+encodeURIComponent(ipSel),{credentials:"same-origin",headers:{"Accept":"application/json"}})
  .then(function(r){if(r.status===401){location.href=APP.base+"/login";return null}return r.json()})
  .then(function(j){if(j&&j.ips)renderIPLog(j)}).catch(function(){});
}
function renderIPLog(j){
  var note="distinct IPs: "+(j.total_ips||0)+(j.overflow?(" (+"+j.overflow+" older evicted)"):"");
  if(!j.geo_enabled)note+="  ·  locations off — enable with: ayana-cdn geo on";
  $("ipNote").textContent=note;
  var wrap=$("iplog");wrap.innerHTML="";
  if(!(j.ips||[]).length){wrap.appendChild(el("div","no client IPs recorded yet for this backend","muted"));return;}
  var t=el("table"),h=el("tr");
  ["Client IP","Hits","Location","First seen","Last seen"].forEach(function(c){h.appendChild(el("th",c))});
  t.appendChild(h);
  j.ips.forEach(function(r){
    var tr=el("tr");
    tr.appendChild(el("td",r.ip));
    tr.appendChild(el("td",r.count));
    var loc="";
    if(r.country==="private")loc="private";
    else if(r.city||r.country||r.cc)loc=[r.city,r.country||r.cc].filter(Boolean).join(", ");
    else if(j.geo_enabled)loc="…";
    tr.appendChild(el("td",loc));
    tr.appendChild(el("td",r.first?new Date(r.first).toLocaleString():""));
    tr.appendChild(el("td",r.last?new Date(r.last).toLocaleString():""));
    t.appendChild(tr);
  });
  wrap.appendChild(t);
}

function render(d){
  $("who").textContent=APP.user+" · "+(d.cdn_hosts||[]).join(", ");
  var mode=$("mode");mode.textContent=d.draining?"draining":"serving";mode.className="pill "+(d.draining?"down":"up");
  var cd=$("cards");cd.innerHTML="";
  var c=d.connections||{};
  card(cd,"Version",d.version,d.go);
  card(cd,"Uptime",dur(d.uptime_seconds),"gen "+d.config_generation);
  card(cd,"Connections",c.active!=null?c.active:0,"cap "+((c.max>0)?c.max:"∞")+" · "+(c.accepted||0)+" total");
  card(cd,"Tunnels open",d.tunnels_active!=null?d.tunnels_active:0,null);
  card(cd,"Refused",(c.rejected_global_cap||0)+(c.rejected_ip_rate||0)+(c.rejected_ip_conns||0),"cap/rate/ip");
  if(c.udp_sessions||c.udp_sessions_max)card(cd,"UDP sessions",c.udp_sessions||0,"cap "+((c.udp_sessions_max>0)?c.udp_sessions_max:"∞"));
  (d.certificates||[]).forEach(function(ci){
    var left=Math.round((new Date(ci.expires)-Date.now())/86400000);
    card(cd,"Cert "+ci.host,left+"d","expires "+(ci.expires||"").slice(0,10));
  });
  renderDomains(d);
  renderBackends(d);
  renderIPSection(d);
  var rt=d.runtime||{};var rc=$("runtime");rc.innerHTML="";
  card(rc,"Goroutines",rt.goroutines,null);
  card(rc,"Heap",bytes(rt.heap_inuse_bytes),"stacks "+bytes(rt.stack_inuse_bytes));
  card(rc,"Sys mem",bytes(rt.sys_bytes),null);
  card(rc,"Open FDs",rt.open_fds,"of "+rt.max_fds);
  prev.t=Date.now();
  $("updated").textContent="updated "+new Date().toLocaleTimeString()+" · refreshes every 3s";
}

function load(){
  fetch(APP.base+"/api/status",{credentials:"same-origin",headers:{"Accept":"application/json"}})
  .then(function(r){if(r.status===401){location.href=APP.base+"/login";return null}return r.json()})
  .then(function(d){if(d){renderControls();render(d)}})
  .catch(function(e){flash("status error: "+e,false)});
}
renderControls();
load();
setInterval(load,3000);
`
