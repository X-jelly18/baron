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
// server-generated, validated strings. Charts are inline SVG built with
// createElementNS and numeric geometry only; no external scripts or styles are
// loaded, and no inline style attributes are emitted (dynamic sizing is done
// through the CSSOM, which the CSP permits).

const panelCSS = `
:root{
  color-scheme:dark light;
  --bg:#0b0e14; --bg2:#141a23; --bg3:#1b2430; --bg4:#222c3a;
  --bd:#26303d; --bd2:#334256;
  --fg:#e6edf3; --fg2:#aeb9c7; --muted:#7d8da0;
  --accent:#2f81f7; --up:#3fb950; --down:#58a6ff; --danger:#f85149; --warn:#d29922;
  --shadow:0 1px 2px rgba(0,0,0,.4),0 4px 16px rgba(0,0,0,.25);
  --r:10px;
}
@media (prefers-color-scheme:light){:root:not([data-theme=dark]){
  --bg:#f4f6fa; --bg2:#ffffff; --bg3:#f0f3f8; --bg4:#e7ecf3;
  --bd:#dbe2ea; --bd2:#c7d2df;
  --fg:#111823; --fg2:#3b4653; --muted:#64748b;
  --accent:#1f6feb; --up:#1a7f37; --down:#1f6feb; --danger:#cf222e; --warn:#9a6700;
  --shadow:0 1px 2px rgba(16,24,40,.06),0 6px 20px rgba(16,24,40,.08);
}}
*{box-sizing:border-box}
html,body{margin:0}
body{font:14px/1.55 system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
  background:var(--bg);color:var(--fg);-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none}
.tnum{font-variant-numeric:tabular-nums}

header{display:flex;align-items:center;gap:12px;padding:11px 18px;border-bottom:1px solid var(--bd);
  background:color-mix(in srgb,var(--bg2) 92%,transparent);backdrop-filter:blur(8px);
  position:sticky;top:0;z-index:20;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:9px;font-weight:650;font-size:15px}
.dot{width:16px;height:16px;border-radius:5px;background:linear-gradient(135deg,var(--accent),var(--up));
  box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 22%,transparent)}
header .sp{flex:1}
.hchips{display:flex;gap:7px;align-items:center}
.chip{display:inline-flex;align-items:center;gap:5px;background:var(--bg3);border:1px solid var(--bd);
  border-radius:999px;padding:3px 10px;font-size:12px;color:var(--fg2);white-space:nowrap}
.chip b{color:var(--fg);font-weight:600}
.chip .ar{font-size:11px}
.up-c{color:var(--up)}.down-c{color:var(--down)}
.who{color:var(--muted);font-size:12.5px;max-width:42vw;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
main{max-width:1200px;margin:0 auto;padding:18px}

.pill{display:inline-block;padding:1px 9px;border-radius:999px;font-size:11.5px;font-weight:600;letter-spacing:.02em}
.up{background:color-mix(in srgb,var(--up) 18%,transparent);color:var(--up)}
.down{background:color-mix(in srgb,var(--danger) 18%,transparent);color:var(--danger)}
.off{background:var(--bg4);color:var(--muted)}
.neutral{background:color-mix(in srgb,var(--accent) 16%,transparent);color:var(--accent)}

.btn{font:inherit;cursor:pointer;border:1px solid var(--bd2);background:var(--bg3);color:var(--fg);
  border-radius:8px;padding:6px 11px;transition:background .12s,border-color .12s}
.btn:hover{background:var(--bg4)}
.btn:active{transform:translateY(1px)}
.btn.sm{padding:4px 9px;font-size:12.5px;border-radius:7px}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn.primary:hover{filter:brightness(1.08)}
.btn.danger{border-color:color-mix(in srgb,var(--danger) 55%,var(--bd2));color:var(--danger)}
.btn.danger:hover{background:color-mix(in srgb,var(--danger) 14%,transparent)}
.btn.ghost{background:transparent;border-color:transparent;color:var(--muted);padding:4px 7px}
.btn.ghost:hover{background:var(--bg3);color:var(--fg)}
.x{cursor:pointer;color:var(--danger);border:none;background:none;font-size:16px;line-height:1;padding:2px 6px;border-radius:6px}
.x:hover{background:color-mix(in srgb,var(--danger) 14%,transparent)}

.card{background:var(--bg2);border:1px solid var(--bd);border-radius:var(--r);box-shadow:var(--shadow)}
.muted{color:var(--muted)}
.err{background:color-mix(in srgb,var(--danger) 14%,transparent);color:var(--danger);
  border:1px solid color-mix(in srgb,var(--danger) 45%,transparent);border-radius:8px;padding:9px 13px;margin-bottom:12px}
.ok{background:color-mix(in srgb,var(--up) 14%,transparent);color:var(--up);
  border:1px solid color-mix(in srgb,var(--up) 40%,transparent);border-radius:8px;padding:9px 13px;margin-bottom:12px}

/* hero throughput */
.hero{background:var(--bg2);border:1px solid var(--bd);border-radius:var(--r);box-shadow:var(--shadow);
  padding:15px 16px 8px;margin-bottom:16px}
.hero-top{display:flex;align-items:flex-end;gap:22px;flex-wrap:wrap;margin-bottom:8px}
.hero-top .ttl{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:0 0 3px}
.big{display:flex;gap:26px;flex-wrap:wrap}
.big.end{justify-content:flex-end}
.big .n{font-size:26px;font-weight:700;line-height:1.1}
.big .u{font-size:12px;color:var(--muted)}
.hero .right{margin-left:auto;text-align:right}

/* chart host: SVG plot + HTML overlays, crisp text, no inline styles */
.chart{position:relative;width:100%;overflow:hidden}
.chart svg{display:block;width:100%;height:100%;position:absolute;inset:0}
.chart .yl{position:absolute;left:6px;font-size:10.5px;color:var(--muted);transform:translateY(-50%);pointer-events:none}
.chart .lg{position:absolute;top:6px;right:8px;display:flex;gap:11px;font-size:11px;color:var(--fg2);pointer-events:none}
.chart .lg i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:4px;vertical-align:-1px}
.chart .cap{position:absolute;left:50%;top:44%;transform:translate(-50%,-50%);color:var(--muted);font-size:12px;pointer-events:none}
.tip{position:fixed;z-index:60;pointer-events:none;background:var(--bg4);border:1px solid var(--bd2);
  border-radius:7px;padding:6px 9px;font-size:11.5px;color:var(--fg);box-shadow:var(--shadow);display:none;white-space:nowrap}
.tip .t{color:var(--muted);margin-bottom:2px}
.spark{position:relative;width:100%;height:42px}
.spark svg{display:block;width:100%;height:100%}

/* KPI tiles */
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:6px}
.tile{background:var(--bg2);border:1px solid var(--bd);border-radius:var(--r);padding:12px 14px;box-shadow:var(--shadow)}
.tile .k{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.05em}
.tile .v{font-size:22px;font-weight:700;margin-top:3px;word-break:break-word}
.tile .s{color:var(--muted);font-size:12px;margin-top:2px}

.bar{display:flex;align-items:center;gap:10px;margin:26px 0 10px;flex-wrap:wrap}
.bar h2{margin:0;font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;flex:1}

/* backend cards */
.bgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,330px),1fr));gap:13px}
.bk{background:var(--bg2);border:1px solid var(--bd);border-radius:var(--r);box-shadow:var(--shadow);
  padding:13px 14px;display:flex;flex-direction:column;gap:10px}
.bk.dis{opacity:.62}
.bk-h{display:flex;align-items:center;gap:8px}
.bk-h .nm{font-weight:650;font-size:15px}
.bk-h .pt{color:var(--muted);font-size:12.5px}
.bk-h .sp{flex:1}
.metrics{display:grid;grid-template-columns:1fr 1fr;gap:7px 14px}
.metric{display:flex;flex-direction:column}
.metric .l{font-size:10.5px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.metric .d{font-size:15px;font-weight:600;margin-top:1px}
.ratebar{display:flex;gap:16px;align-items:center;padding:7px 10px;background:var(--bg3);border-radius:8px}
.ratebar .r{display:flex;align-items:baseline;gap:6px}
.ratebar .r .n{font-size:16px;font-weight:700}
.ratebar .r .l{font-size:11px;color:var(--muted)}
.bk-act{display:flex;gap:6px;flex-wrap:wrap}
.detail{border-top:1px solid var(--bd);padding-top:10px;display:flex;flex-direction:column;gap:9px}
.ups{display:flex;flex-direction:column;gap:4px}
.ups .u{display:flex;align-items:center;gap:7px;font-size:12.5px}
.ups .u .a{flex:1;word-break:break-all}
.classes{display:flex;gap:6px;flex-wrap:wrap}
.cl{font-size:11px;padding:2px 7px;border-radius:6px;background:var(--bg3);color:var(--fg2)}

/* tables (domains, IPs) */
table{width:100%;border-collapse:collapse;background:var(--bg2);border:1px solid var(--bd);
  border-radius:var(--r);overflow:hidden;box-shadow:var(--shadow)}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--bd);font-size:13px;vertical-align:middle}
th{color:var(--muted);font-weight:600;background:color-mix(in srgb,var(--bg3) 70%,transparent);
  font-size:11px;text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:none}
td .sparkcell{width:130px}
/* wide tables scroll inside their own section instead of the whole page (phones) */
#domains,#iplog{overflow-x:auto}
#domains table,#iplog table{min-width:520px}

/* forms */
form.add{background:var(--bg3);border:1px solid var(--bd);border-radius:var(--r);padding:12px 13px;margin:2px 0 10px;
  display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}
form.add .f{display:flex;flex-direction:column;gap:3px}
form.add label{font-size:10.5px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
form.add input,form.add select{padding:7px 9px;border-radius:8px;border:1px solid var(--bd2);background:var(--bg);color:var(--fg);font:inherit}
form.add input:focus,form.add select:focus,.login input:focus{outline:2px solid color-mix(in srgb,var(--accent) 55%,transparent);outline-offset:0;border-color:var(--accent)}
form.add input[type=text]{min-width:150px}
.hint{color:var(--muted);font-size:12px;margin:2px 0 10px}

/* login */
.login{max-width:340px;margin:13vh auto;background:var(--bg2);border:1px solid var(--bd);
  border-radius:14px;padding:26px;box-shadow:var(--shadow)}
.login .brand{margin-bottom:4px}
.login p{color:var(--muted);margin:0 0 16px;font-size:13px}
.login label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin:12px 0 4px}
.login input{width:100%;padding:10px 11px;border-radius:9px;border:1px solid var(--bd2);background:var(--bg);color:var(--fg);font:inherit}
.login button{width:100%;margin-top:18px;padding:11px}
.foot{color:var(--muted);font-size:12px;margin-top:20px;text-align:center}
.nojs{padding:18px}

@media(max-width:560px){
  main{padding:14px 16px}
  .big .n{font-size:22px}
  .tiles{grid-template-columns:repeat(auto-fit,minmax(130px,1fr))}
  .who{max-width:34vw}
}
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
	b.WriteString(`<div class="brand"><span class="dot"></span>ayana-cdn</div><p>Sign in to the control panel.</p>`)
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
	b.WriteString(`<header><span class="brand"><span class="dot"></span>ayana-cdn</span>`)
	b.WriteString(`<span class="pill off" id="mode">&nbsp;</span>`)
	b.WriteString(`<span class="hchips" id="hchips"></span>`)
	b.WriteString(`<span class="sp"></span>`)
	b.WriteString(`<span class="who" id="who"></span>`)
	b.WriteString(`<form method="post" action="logout" id="logoutForm"><input type="hidden" name="csrf" id="csrfField">`)
	b.WriteString(`<button class="btn sm" type="submit">Sign out</button></form></header>`)
	b.WriteString(`<main><div id="msg"></div>`)
	b.WriteString(`<section class="hero"><div class="hero-top"><div><div class="ttl">Live throughput</div>`)
	b.WriteString(`<div class="big"><div><div class="n up-c tnum" id="hUp">–</div><div class="u">upload ↑</div></div>`)
	b.WriteString(`<div><div class="n down-c tnum" id="hDown">–</div><div class="u">download ↓</div></div></div></div>`)
	b.WriteString(`<div class="right"><div class="ttl">Transferred (since start)</div><div class="big end">`)
	b.WriteString(`<div><div class="n tnum" id="hTot">–</div><div class="u" id="hTotSub">up / down</div></div></div></div></div>`)
	b.WriteString(`<div class="chart" id="chartTotal"></div></section>`)
	b.WriteString(`<div class="tiles" id="tiles"></div>`)
	b.WriteString(`<div id="controls" class="bar"></div>`)
	b.WriteString(`<div class="bar"><h2>Domains</h2><span id="domainCtl"></span></div>`)
	b.WriteString(`<div id="domainForm"></div><div id="domains"></div>`)
	b.WriteString(`<div class="bar"><h2>Backends &amp; paths</h2><span id="backendCtl"></span></div>`)
	b.WriteString(`<div id="backendForm"></div><div id="backends"></div>`)
	b.WriteString(`<div class="bar"><h2>Client IPs</h2><span id="ipCtl"></span></div>`)
	b.WriteString(`<div id="ipNote" class="hint"></div><div id="iplog"></div>`)
	b.WriteString(`<div class="bar"><h2>Runtime</h2></div><div class="tiles" id="runtime"></div>`)
	b.WriteString(`<div class="foot muted" id="updated"></div></main>`)
	b.WriteString(`<div class="tip" id="tip"></div>`)
	b.WriteString(`<noscript><p class="nojs muted">JavaScript is required. The raw status is at <a href="api/status">api/status</a>.</p></noscript>`)
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
var $=function(id){return document.getElementById(id)};
var SVGNS="http://www.w3.org/2000/svg";
function el(tag,txt,cls){var e=document.createElement(tag);if(txt!=null)e.textContent=txt;if(cls)e.className=cls;return e}
function svg(tag,a){var e=document.createElementNS(SVGNS,tag);if(a)for(var k in a)e.setAttribute(k,a[k]);return e}
function bytes(n){n=Number(n)||0;var u=["B","KiB","MiB","GiB","TiB","PiB"],i=0;while(n>=1024&&i<u.length-1){n/=1024;i++}return (i?n.toFixed(1):Math.round(n))+" "+u[i]}
function dur(sec){sec=Number(sec)||0;if(sec>=86400)return Math.floor(sec/86400)+"d"+Math.floor((sec%86400)/3600)+"h";if(sec>=3600)return Math.floor(sec/3600)+"h"+Math.floor((sec%3600)/60)+"m";if(sec>=60)return Math.floor(sec/60)+"m"+(sec%60)+"s";return sec+"s"}
function mbps(v){v=Number(v)||0;if(v<0.01)return "0";return v<10?v.toFixed(2):(v<100?v.toFixed(1):Math.round(v).toString())}
function mbpsU(v){return mbps(v)+" Mbps"}
$("csrfField").value=APP.csrf;

var SERIES={interval_ms:2000,points:0,total:{up:[],down:[]},backends:{},hosts:{}};
var IVS=2;                 // sampling interval, seconds (from the series API)
var ipSel=null;            // selected backend for the Client IPs section
var expanded={};           // backend name -> detail chart open

// rates(pair) converts a {up:[bytes],down:[bytes]} interval series into Mbps arrays.
function rates(pair){
  var up=[],down=[],u=(pair&&pair.up)||[],d=(pair&&pair.down)||[],i;
  for(i=0;i<u.length;i++)up.push(u[i]*8/1e6/IVS);
  for(i=0;i<d.length;i++)down.push(d[i]*8/1e6/IVS);
  return {up:up,down:down};
}
function lastRate(pair){
  var r=rates(pair),n=r.up.length;
  return {up:n?r.up[n-1]:0,down:n?r.down[n-1]:0};
}
function niceMax(v){if(!(v>0))return 1;var p=Math.pow(10,Math.floor(Math.log10(v))),f=v/p;var m=f<=1?1:f<=2?2:f<=5?5:10;return m*p}

// A spark's SVG paths are created once (buildSpark) and only their geometry
// (the d attribute) is updated on refresh (updateSpark), so a 2 s tick stays
// cheap even with dozens of backends. vector-effect keeps strokes crisp despite
// the non-uniform viewBox scaling, so nothing has to be measured.
function pathLineD(a,x,y){var d="",i;for(i=0;i<a.length;i++)d+=(i?"L":"M")+x(i).toFixed(1)+" "+y(a[i]).toFixed(1);return d}
function pathAreaD(a,x,y,H){var d="M"+x(0).toFixed(1)+" "+H.toFixed(1),i;for(i=0;i<a.length;i++)d+="L"+x(i).toFixed(1)+" "+y(a[i]).toFixed(1);return d+"L"+x(a.length-1).toFixed(1)+" "+H+"Z"}
function buildSpark(box){
  var W=240,H=42,s=svg("svg",{viewBox:"0 0 "+W+" "+H,preserveAspectRatio:"none"});
  var area=svg("path",{fill:"var(--down)","fill-opacity":0.22,stroke:"none"});
  var up=svg("path",{fill:"none",stroke:"var(--up)","stroke-width":1.5,"stroke-linejoin":"round","vector-effect":"non-scaling-stroke"});
  var dn=svg("path",{fill:"none",stroke:"var(--down)","stroke-width":1.5,"stroke-linejoin":"round","vector-effect":"non-scaling-stroke"});
  s.appendChild(area);s.appendChild(up);s.appendChild(dn);
  box.textContent="";box.appendChild(s);
  return {W:W,H:H,area:area,up:up,dn:dn};
}
function updateSpark(sp,pair){
  var r=rates(pair),n=Math.max(r.up.length,r.down.length);
  if(n<2){sp.area.setAttribute("d","");sp.up.setAttribute("d","");sp.dn.setAttribute("d","");return}
  var mx=niceMax(Math.max(Math.max.apply(null,r.up),Math.max.apply(null,r.down),0));
  var x=function(i){return i*(sp.W/(n-1))},y=function(v){return sp.H-2-(v/mx)*(sp.H-4)};
  sp.area.setAttribute("d",pathAreaD(r.down,x,y,sp.H));
  sp.up.setAttribute("d",pathLineD(r.up,x,y));
  sp.dn.setAttribute("d",pathLineD(r.down,x,y));
}
function linePath(a,x,y,color,wd){return svg("path",{d:pathLineD(a,x,y),fill:"none",stroke:color,"stroke-width":wd,"stroke-linejoin":"round","vector-effect":"non-scaling-stroke"})}
function areaPath(a,x,y,H,color,op){return svg("path",{d:pathAreaD(a,x,y,H),fill:color,"fill-opacity":op,stroke:"none"})}

// drawChart renders a full area chart (grid + y labels + legend + hover) into
// host. up=green area, down=blue area. Text lives in HTML overlays so the
// non-uniform SVG scaling never stretches it.
function drawChart(host,pair,h){
  host.textContent="";
  host.style.height=h+"px";
  var W=1000,r=rates(pair),n=Math.max(r.up.length,r.down.length);
  var s=svg("svg",{viewBox:"0 0 "+W+" "+h,preserveAspectRatio:"none"});
  host.appendChild(s);
  if(n<2){host.appendChild(el("div","collecting data…","cap"));return}
  var peak=Math.max(Math.max.apply(null,r.up),Math.max.apply(null,r.down),0);
  var mx=niceMax(peak);
  var padT=8,padB=4,x=function(i){return i*(W/(n-1))},y=function(v){return padT+(1-v/mx)*(h-padT-padB)};
  var g;[0,0.5,1].forEach(function(f){
    var yy=padT+(1-f)*(h-padT-padB);
    s.appendChild(svg("line",{x1:0,y1:yy,x2:W,y2:yy,stroke:"var(--bd)","stroke-width":1,"vector-effect":"non-scaling-stroke"}));
    var lab=el("span",mbps(mx*f)+(f===1?" Mbps":""),"yl");lab.style.top=(yy/h*100)+"%";host.appendChild(lab);
  });
  s.appendChild(areaPath(r.down,x,y,h,"var(--down)",0.20));
  s.appendChild(areaPath(r.up,x,y,h,"var(--up)",0.18));
  s.appendChild(linePath(r.down,x,y,"var(--down)",1.6));
  s.appendChild(linePath(r.up,x,y,"var(--up)",1.6));
  var cr=svg("line",{x1:0,y1:0,x2:0,y2:h,stroke:"var(--fg2)","stroke-width":1,"vector-effect":"non-scaling-stroke","stroke-dasharray":"3 3",opacity:0});
  s.appendChild(cr);
  var lg=el("div",null,"lg");
  var a1=el("span");var i1=el("i");i1.style.background="var(--up)";a1.appendChild(i1);a1.appendChild(document.createTextNode("up"));
  var a2=el("span");var i2=el("i");i2.style.background="var(--down)";a2.appendChild(i2);a2.appendChild(document.createTextNode("down"));
  lg.appendChild(a1);lg.appendChild(a2);host.appendChild(lg);
  // hover
  var tip=$("tip");
  host.onmousemove=function(ev){
    var rect=host.getBoundingClientRect();if(rect.width<=0)return;
    var frac=Math.min(1,Math.max(0,(ev.clientX-rect.left)/rect.width));
    var i=Math.round(frac*(n-1));
    cr.setAttribute("x1",x(i));cr.setAttribute("x2",x(i));cr.setAttribute("opacity",1);
    var ago=(n-1-i)*IVS;
    tip.textContent="";
    var tt=el("div",ago===0?"now":("-"+dur(ago)),"t");tip.appendChild(tt);
    tip.appendChild(el("div","↑ "+mbpsU(r.up[i]||0)));
    tip.appendChild(el("div","↓ "+mbpsU(r.down[i]||0)));
    tip.style.display="block";
    var tx=ev.clientX+12,ty=ev.clientY+12;
    if(tx+150>window.innerWidth)tx=ev.clientX-150;
    tip.style.left=tx+"px";tip.style.top=ty+"px";
  };
  host.onmouseleave=function(){cr.setAttribute("opacity",0);$("tip").style.display="none"};
}

function post(path,params,done){
  var body=Object.keys(params).map(function(k){return encodeURIComponent(k)+"="+encodeURIComponent(params[k])}).join("&");
  fetch(APP.base+path,{method:"POST",credentials:"same-origin",
    headers:{"X-CSRF-Token":APP.csrf,"Content-Type":"application/x-www-form-urlencoded"},body:body})
  .then(function(r){return r.json().catch(function(){return{ok:false,error:"HTTP "+r.status}})})
  .then(function(j){done(j)}).catch(function(e){done({ok:false,error:String(e)})});
}
function flash(msg,ok){var m=$("msg");m.textContent="";var d=el("div",msg,ok?"ok":"err");m.appendChild(d);setTimeout(function(){if(m.firstChild===d)m.textContent=""},7000)}
function field(label,node){var f=el("div",null,"f");f.appendChild(el("label",label));f.appendChild(node);return f}
function sel(opts,val){var s=document.createElement("select");opts.forEach(function(o){var op=document.createElement("option");op.value=o;op.textContent=o;if(o===val)op.selected=true;s.appendChild(op)});return s}
function inp(ph,val){var i=document.createElement("input");i.type="text";i.placeholder=ph||"";if(val!=null)i.value=val;return i}

function renderControls(){
  var c=$("controls");c.textContent="";
  if(!APP.control){$("domainCtl").textContent="";$("backendCtl").textContent="";return}
  c.appendChild(el("h2","Control"));
  var b=el("button","↻ Reload config","btn sm");
  b.addEventListener("click",function(){b.disabled=true;post("/api/reload",{},function(j){b.disabled=false;flash(j.ok?j.message:("reload: "+j.error),j.ok);tick()})});
  c.appendChild(b);
  if(!$("domainCtl").firstChild){
    var ad=el("button","+ Add domain","btn sm");ad.addEventListener("click",domainForm);$("domainCtl").appendChild(ad);
    var ab=el("button","+ Add backend / path","btn sm");ab.addEventListener("click",function(){backendForm(null)});$("backendCtl").appendChild(ab);
  }
}

function domainForm(){
  var wrap=$("domainForm");wrap.textContent="";
  var f=document.createElement("form");f.className="add";
  var host=inp("sub.example.com");
  f.appendChild(field("New domain (must resolve to this server)",host));
  var save=el("button","Add","btn primary sm");save.type="submit";
  var cancel=el("button","Cancel","btn sm");cancel.type="button";cancel.addEventListener("click",function(){wrap.textContent=""});
  f.appendChild(field(" ",save));f.appendChild(field(" ",cancel));
  f.addEventListener("submit",function(e){e.preventDefault();post("/api/host",{action:"add",host:host.value},function(j){flash(j.ok?j.message:("error: "+j.error),j.ok);if(j.ok)wrap.textContent="";tick()})});
  wrap.appendChild(f);host.focus();
}

function backendForm(bk){
  var wrap=$("backendForm");wrap.textContent="";
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
  var cancel=el("button","Cancel","btn sm");cancel.type="button";cancel.addEventListener("click",function(){wrap.textContent=""});
  f.appendChild(field(" ",save));f.appendChild(field(" ",cancel));
  var hint=el("div","Local service on this VPS: set Proto = http (or https) and Upstreams = 127.0.0.1:PORT. Tunnels: wss/ws. Clients reach it at /"+(editing?bk.name:"<name>")+"/.","hint");
  f.addEventListener("submit",function(e){e.preventDefault();
    post("/api/backend",{action:editing?"update":"add",name:name.value,proto:proto.value,upstreams:ups.value,
      host:host.value,listen:listen.value,strip:strip.value,relay:relay.value,lb:lb.value,insecure:insecure.value},
      function(j){flash(j.ok?j.message:("error: "+j.error),j.ok);if(j.ok)wrap.textContent="";tick()});
  });
  wrap.appendChild(f);wrap.appendChild(hint);name.focus();
}
function hostToggle(action,host){post("/api/host",{action:action,host:host},function(j){flash(j.ok?j.message:("error: "+j.error),j.ok);tick()})}
function backendAction(action,name){post("/api/backend",{action:action,name:name},function(j){flash(j.ok?j.message:("error: "+j.error),j.ok);tick()})}

function tile(parent,k,v,s){var c=el("div",null,"tile");c.appendChild(el("div",k,"k"));c.appendChild(el("div",String(v),"v"));if(s!=null)c.appendChild(el("div",String(s),"s"));parent.appendChild(c)}

function renderHero(d){
  var tr=lastRate(SERIES.total);
  $("hUp").textContent=mbpsU(tr.up);
  $("hDown").textContent=mbpsU(tr.down);
  var up=0,down=0;(d.backends||[]).forEach(function(b){up+=Number(b.bytes_up)||0;down+=Number(b.bytes_down)||0});
  $("hTot").textContent=bytes(up+down);
  $("hTotSub").textContent="↑ "+bytes(up)+"  ·  ↓ "+bytes(down);
  drawChart($("chartTotal"),SERIES.total,170);
  // header chips
  var hc=$("hchips");hc.textContent="";
  var c1=el("span",null,"chip");c1.appendChild(el("span","↑","ar up-c"));var b1=el("b",mbps(tr.up));c1.appendChild(b1);c1.appendChild(document.createTextNode("Mbps"));
  var c2=el("span",null,"chip");c2.appendChild(el("span","↓","ar down-c"));var b2=el("b",mbps(tr.down));c2.appendChild(b2);c2.appendChild(document.createTextNode("Mbps"));
  hc.appendChild(c1);hc.appendChild(c2);
}

function renderTiles(d){
  var t=$("tiles");t.textContent="";
  var c=d.connections||{};
  tile(t,"Connections",c.active!=null?c.active:0,"cap "+((c.max>0)?c.max:"∞")+" · "+(c.accepted||0)+" total");
  tile(t,"Tunnels open",d.tunnels_active!=null?d.tunnels_active:0,(d.backends||[]).length+" backends");
  var tr=lastRate(SERIES.total);
  tile(t,"Throughput","↑"+mbps(tr.up)+" ↓"+mbps(tr.down),"Mbps now");
  tile(t,"Uptime",dur(d.uptime_seconds),"gen "+d.config_generation);
  var refused=(c.rejected_global_cap||0)+(c.rejected_ip_rate||0)+(c.rejected_ip_conns||0);
  tile(t,"Refused",refused,"cap/rate/ip");
  if(c.udp_sessions||c.udp_sessions_max)tile(t,"UDP sessions",c.udp_sessions||0,"cap "+((c.udp_sessions_max>0)?c.udp_sessions_max:"∞"));
  (d.certificates||[]).forEach(function(ci){
    var left=Math.round((new Date(ci.expires)-Date.now())/86400000);
    tile(t,"Cert "+ci.host,left+"d","expires "+(ci.expires||"").slice(0,10));
  });
}

// Domains and backends are rendered incrementally: the row/card DOM is built
// once (and rebuilt only when the SET of domains/backends changes), then each
// refresh updates just the changing values and redraws the spark in place. This
// keeps a 2 s refresh smooth even with dozens of backends.
var domState={order:"",rows:{}};
function renderDomains(d){
  var wrap=$("domains"),list=d.host_traffic||[];
  var order=list.map(function(h){return h.host}).join("\u0001")+"|"+APP.control;
  if(domState.order!==order){
    wrap.textContent="";domState.rows={};
    var t=el("table"),h=el("tr");
    var cols=["Domain","Requests","Active","Rate ↑/↓","Total up/down","Last 3 min"];if(APP.control)cols.push("");
    cols.forEach(function(c){h.appendChild(el("th",c))});t.appendChild(h);
    list.forEach(function(ht){
      var tr=el("tr"),refs={};
      tr.appendChild(el("td",ht.host));
      refs.req=el("td","","tnum");tr.appendChild(refs.req);
      refs.act=el("td","","tnum");tr.appendChild(refs.act);
      refs.rate=el("td","","tnum");tr.appendChild(refs.rate);
      refs.tot=el("td","","tnum");tr.appendChild(refs.tot);
      var sc=el("td",null,"sparkcell");refs.sp=el("div",null,"spark");sc.appendChild(refs.sp);tr.appendChild(sc);refs.spark=buildSpark(refs.sp);
      if(APP.control){var td=el("td");if(ht.host!=="other"){var x=el("button","×","x");x.title="remove domain";(function(hn){x.addEventListener("click",function(){if(confirm("Remove domain "+hn+"?"))hostToggle("remove",hn)})})(ht.host);td.appendChild(x)}tr.appendChild(td)}
      t.appendChild(tr);domState.rows[ht.host]=refs;
    });
    wrap.appendChild(t);domState.order=order;
  }
  list.forEach(function(ht){
    var r=domState.rows[ht.host];if(!r)return;
    var rt=lastRate(SERIES.hosts[ht.host]);
    r.req.textContent=ht.requests||0;
    r.act.textContent=ht.active||0;
    r.rate.textContent="↑"+mbps(rt.up)+" ↓"+mbps(rt.down);
    r.tot.textContent=bytes(ht.bytes_up)+" / "+bytes(ht.bytes_down);
    updateSpark(r.spark,SERIES.hosts[ht.host]);
  });
}

function metricRef(parent,label){var m=el("div",null,"metric");m.appendChild(el("div",label,"l"));var d=el("div","","d");m.appendChild(d);parent.appendChild(m);return d}
function statePill(b){
  if(b.disabled)return {t:"disabled",c:"pill off"};
  var anyUp=(b.upstreams||[]).some(function(u){return u.healthy});
  return {t:anyUp?"up":"down",c:anyUp?"pill up":"pill down"};
}
function upRows(box,b){
  box.textContent="";
  (b.upstreams||[]).forEach(function(u){
    var row=el("div",null,"u");
    row.appendChild(el("span",u.healthy?"up":"down",u.healthy?"pill up":"pill down"));
    row.appendChild(el("span",u.addr,"a"));
    if(u.active)row.appendChild(el("span",u.active+" open","muted"));
    box.appendChild(row);
    if(!u.healthy&&u.last_error)box.appendChild(el("div",u.last_error,"muted"));
  });
}
function clsRow(box,b){
  box.textContent="";
  var cls=b.responses||{};Object.keys(cls).forEach(function(k){box.appendChild(el("span",k+": "+cls[k],"cl"))});
}
function buildCard(b){
  var refs={},card=el("div",null,"bk"+(b.disabled?" dis":""));
  var hd=el("div",null,"bk-h");
  hd.appendChild(el("span",b.name,"nm"));
  hd.appendChild(el("span",b.listen?("udp "+b.listen):b.path,"pt"));
  hd.appendChild(el("span",null,"sp"));
  hd.appendChild(el("span",b.proto+(b.relay==="always"?" raw":""),"pill neutral"));
  var sp0=statePill(b);refs.state=el("span",sp0.t,sp0.c);hd.appendChild(refs.state);
  card.appendChild(hd);
  var rb=el("div",null,"ratebar");
  var ru=el("div",null,"r");refs.rup=el("span","","n up-c");ru.appendChild(refs.rup);ru.appendChild(el("span","Mbps ↑ up","l"));
  var rd=el("div",null,"r");refs.rdown=el("span","","n down-c");rd.appendChild(refs.rdown);rd.appendChild(el("span","Mbps ↓ down","l"));
  rb.appendChild(ru);rb.appendChild(rd);card.appendChild(rb);
  refs.sp=el("div",null,"spark");card.appendChild(refs.sp);refs.spark=buildSpark(refs.sp);
  var mt=el("div",null,"metrics");
  refs.tup=metricRef(mt,"Total up");refs.tdown=metricRef(mt,"Total down");
  refs.open=metricRef(mt,"Open");refs.ttot=metricRef(mt,"Total tunnels");
  refs.failed=metricRef(mt,"Failed");
  refs.udp=(b.packets_up!=null||b.packets_down!=null);
  refs.extra=metricRef(mt,refs.udp?"Packets u/d":"Cap rejects");
  card.appendChild(mt);
  var act=el("div",null,"bk-act");
  var det=el("button",expanded[b.name]?"Hide details":"Details","btn ghost sm");
  (function(n){det.addEventListener("click",function(){expanded[n]=!expanded[n];bkState.order="";renderBackends(lastStatus)})})(b.name);
  act.appendChild(det);
  if(APP.control){
    var tg=el("button",b.disabled?"Enable":"Disable","btn sm"+(b.disabled?"":" danger"));
    (function(n,dis){tg.addEventListener("click",function(){backendAction(dis?"enable":"disable",n)})})(b.name,b.disabled);
    var ed=el("button","Edit","btn sm");(function(bb){ed.addEventListener("click",function(){backendForm(bb)})})(b);
    var rm=el("button","Remove","btn sm");(function(n){rm.addEventListener("click",function(){if(confirm("Remove backend "+n+"?"))backendAction("remove",n)})})(b.name);
    act.appendChild(tg);act.appendChild(ed);act.appendChild(rm);
  }
  card.appendChild(act);
  if(expanded[b.name]){
    var dt=el("div",null,"detail");
    refs.chart=el("div",null,"chart");dt.appendChild(refs.chart);
    refs.ups=el("div",null,"ups");dt.appendChild(refs.ups);
    refs.cls=el("div",null,"classes");dt.appendChild(refs.cls);
    card.appendChild(dt);
  }
  return {el:card,refs:refs};
}
function updateCard(c,b){
  if(!c)return;var refs=c.refs,pair=SERIES.backends[b.name],rt=lastRate(pair);
  var sp0=statePill(b);if(refs.state.textContent!==sp0.t){refs.state.textContent=sp0.t;refs.state.className=sp0.c}
  refs.rup.textContent=mbps(rt.up);refs.rdown.textContent=mbps(rt.down);
  refs.tup.textContent=bytes(b.bytes_up);refs.tdown.textContent=bytes(b.bytes_down);
  refs.open.textContent=b.tunnels_active;refs.ttot.textContent=b.tunnels_total;refs.failed.textContent=b.failures;
  refs.extra.textContent=refs.udp?((b.packets_up||0)+" / "+(b.packets_down||0)):(b.capacity_rejections||0);
  updateSpark(refs.spark,pair);
  if(refs.chart){drawChart(refs.chart,pair,140);upRows(refs.ups,b);clsRow(refs.cls,b)}
}
var bkState={order:"",cards:{}};
function renderBackends(d){
  var wrap=$("backends"),list=d.backends||[];
  // The order key triggers a full rebuild. It includes every statically-rendered
  // field (name, proto, relay, path/listen) so an Edit that changes them refreshes
  // the header and the packets-vs-cap-rejects label; rate/totals/spark change every
  // tick and are updated in place without a rebuild.
  var order=list.map(function(b){return [b.name,b.proto,b.relay,b.listen||b.path,expanded[b.name]?1:0,b.disabled?1:0].join("~")}).join("\u0001")+"|"+APP.control;
  if(bkState.order!==order){
    wrap.textContent="";bkState.cards={};
    var grid=el("div",null,"bgrid");
    list.forEach(function(b){var c=buildCard(b);bkState.cards[b.name]=c;grid.appendChild(c.el)});
    wrap.appendChild(grid);bkState.order=order;
  }
  list.forEach(function(b){updateCard(bkState.cards[b.name],b)}); // updates values + spark; detail charts drawn after attach
}

function renderIPSection(d){
  var ctl=$("ipCtl");
  var names=(d.backends||[]).map(function(b){return b.name});
  var s=$("ipBackend");
  if(!s){s=document.createElement("select");s.id="ipBackend";s.addEventListener("change",function(){ipSel=s.value;loadIPLog()});ctl.appendChild(s)}
  var want=names.join("\u0001");
  if(s.getAttribute("data-k")!==want){
    s.textContent="";names.forEach(function(n){var o=document.createElement("option");o.value=n;o.textContent=n;s.appendChild(o)});
    s.setAttribute("data-k",want);
  }
  if(!ipSel||names.indexOf(ipSel)<0)ipSel=names[0]||null;
  if(ipSel)s.value=ipSel;
  loadIPLog();
}
function loadIPLog(){
  if(!ipSel){$("iplog").textContent="";$("ipNote").textContent="";return}
  fetch(APP.base+"/api/iplog?backend="+encodeURIComponent(ipSel),{credentials:"same-origin",headers:{"Accept":"application/json"}})
  .then(function(r){if(r.status===401){location.href=APP.base+"/login";return null}return r.json()})
  .then(function(j){if(j&&j.ips)renderIPLog(j)}).catch(function(){});
}
function renderIPLog(j){
  var note="distinct IPs: "+(j.total_ips||0)+(j.overflow?(" (+"+j.overflow+" older evicted)"):"");
  if(!j.geo_enabled)note+="  ·  locations off — enable with: ayana-cdn geo on";
  $("ipNote").textContent=note;
  var wrap=$("iplog");wrap.textContent="";
  if(!(j.ips||[]).length){wrap.appendChild(el("div","no client IPs recorded yet for this backend","muted"));return}
  var t=el("table"),h=el("tr");
  ["Client IP","Hits","Location","First seen","Last seen"].forEach(function(c){h.appendChild(el("th",c))});
  t.appendChild(h);
  j.ips.forEach(function(r){
    var tr=el("tr");
    tr.appendChild(el("td",r.ip));
    tr.appendChild(el("td",r.count,"tnum"));
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

var lastStatus=null;
function render(d){
  lastStatus=d;
  $("who").textContent=APP.user+" · "+(d.cdn_hosts||[]).join(", ");
  var mode=$("mode");mode.textContent=d.draining?"draining":"serving";mode.className="pill "+(d.draining?"down":"up");
  renderHero(d);
  renderTiles(d);
  renderDomains(d);
  renderBackends(d);
  renderIPSection(d);
  var rt=d.runtime||{},rc=$("runtime");rc.textContent="";
  tile(rc,"Goroutines",rt.goroutines);
  tile(rc,"Heap",bytes(rt.heap_inuse_bytes),"stacks "+bytes(rt.stack_inuse_bytes));
  tile(rc,"Sys mem",bytes(rt.sys_bytes));
  tile(rc,"Open FDs",rt.open_fds,"of "+rt.max_fds);
  $("updated").textContent="updated "+new Date().toLocaleTimeString()+" · refreshes every "+IVS+"s";
}

function tick(){
  Promise.all([
    fetch(APP.base+"/api/status",{credentials:"same-origin",headers:{"Accept":"application/json"}}),
    fetch(APP.base+"/api/series",{credentials:"same-origin",headers:{"Accept":"application/json"}})
  ]).then(function(res){
    if(res[0].status===401||res[1].status===401){location.href=APP.base+"/login";return}
    return Promise.all([res[0].json(),res[1].json()]);
  }).then(function(j){
    if(!j)return;
    if(j[1]){SERIES=j[1];IVS=(SERIES.interval_ms||2000)/1000}
    if(j[0]){renderControls();render(j[0])}
  }).catch(function(e){flash("status error: "+e,false)});
}
renderControls();
tick();
setInterval(tick,2000);
`
