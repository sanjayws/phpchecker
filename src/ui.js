import { ADVISORY } from './advisory.js';
import { PROJECT } from './project.js';

// The whole front end as one string so the Worker stays a single deployable file set.
// Client code avoids template literals so it can live inside this one. All dynamic text
// (scan results, headers, help content) is inserted with textContent / createTextNode.
// innerHTML is only ever used for the constant SVG icons defined below.

const ICON_PATHS = {
  shieldCheck: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
  shieldAlert: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4M12 16h.01"/>',
  shieldQ: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .8-1 1.5M12 17h.01"/>',
  info: '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>',
  check: '<path d="M20 6 9 17l-5-5"/>',
  chevron: '<path d="m6 9 6 6 6-6"/>',
  globe: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20"/>',
  github:
    '<path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.9a3.4 3.4 0 0 0-.9-2.6c3-.3 6.1-1.5 6.1-6.7a5.2 5.2 0 0 0-1.4-3.6 4.8 4.8 0 0 0-.1-3.6s-1.1-.3-3.6 1.4a12.3 12.3 0 0 0-6.4 0C6.2 2.8 5.1 3.1 5.1 3.1a4.8 4.8 0 0 0-.1 3.6A5.2 5.2 0 0 0 3.6 10.3c0 5.2 3.1 6.4 6.1 6.7a3.4 3.4 0 0 0-.9 2.6V22"/>',
  arrow: '<path d="M5 12h14M13 6l6 6-6 6"/>',
};
const svg = (name, size = 20) =>
  `<svg viewBox="0 0 24 24" width="${size}" height="${size}" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICON_PATHS[name]}</svg>`;

const PAGE = String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>PHPChecker – php2shell CVE scanner</title>
<meta name="description" content="Scanner for the php2shell PHP vulnerabilities CVE-2026-109618 and CVE-2026-109619, with fixes, workarounds and detection help.">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='%234f46e5' d='M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5z'/%3E%3Cpath d='m8.5 12 2.5 2.5 4.5-5' fill='none' stroke='%23fff' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
<style nonce="__NONCE__">
:root{color-scheme:light;--bg:#fff;--ink:#0f172a;--ink2:#334155;--muted:#64748b;--line:#e2e8f0;--soft:#f8fafc;--accent:#4f46e5;--accent2:#6366f1;--accent-soft:#eef2ff;--accent-line:#c7d2fe;--shadow:0 1px 2px rgba(15,23,42,.05),0 12px 32px -16px rgba(15,23,42,.22)}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--bg);color:var(--ink);font:15px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;-webkit-font-smoothing:antialiased;min-height:100vh;display:flex;flex-direction:column}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
button{font:inherit;color:inherit}
[hidden]{display:none!important}
.ic{display:inline-flex;vertical-align:middle}
.wrap{width:100%;max-width:1040px;margin:0 auto;padding:0 20px}

header.top{position:sticky;top:0;z-index:10;background:rgba(255,255,255,.88);backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
header.top .wrap{display:flex;align-items:center;justify-content:space-between;height:60px}
.brand{display:flex;align-items:center;gap:10px;font-weight:800;font-size:18px;letter-spacing:-.02em;color:var(--ink)}
.brand:hover{text-decoration:none}
.ghbtn{display:inline-flex;align-items:center;gap:8px;border:1px solid var(--line);border-radius:10px;padding:7px 13px;font-size:14px;font-weight:600;color:var(--ink);background:#fff}
.ghbtn:hover{background:var(--soft);text-decoration:none}

.hero{text-align:center;padding:68px 20px 40px;background:radial-gradient(60% 100% at 50% -20%,#e0e7ff 0%,rgba(224,231,255,0) 72%)}
.title{font-size:clamp(20px,4vw,42px);line-height:1.15;font-weight:800;letter-spacing:-.035em;margin:0 0 12px;white-space:nowrap}
.sub{margin:0 auto 32px;color:var(--muted);font-size:17px}
form{max-width:680px;margin:0 auto}
.search{display:flex;align-items:center;gap:10px;background:#fff;border:1px solid var(--line);border-radius:16px;padding:7px 7px 7px 16px;box-shadow:var(--shadow)}
.search:focus-within{border-color:var(--accent2);box-shadow:0 0 0 4px rgba(99,102,241,.16),var(--shadow)}
.search .ic{color:var(--muted)}
.search input{flex:1;min-width:0;height:46px;border:0;outline:0;background:transparent;color:var(--ink);font:17px system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.search input::placeholder{color:#94a3b8}
.btn{display:inline-flex;align-items:center;gap:8px;height:46px;padding:0 22px;border:0;border-radius:11px;background:linear-gradient(180deg,#6366f1,#4f46e5);color:#fff;font-weight:700;font-size:15px;cursor:pointer;white-space:nowrap;box-shadow:0 1px 2px rgba(79,70,229,.45),inset 0 1px 0 rgba(255,255,255,.22)}
.btn .ic{color:#fff}
.btn:hover{filter:brightness(1.07)}
.btn:disabled{opacity:.7;cursor:progress}
.consent{margin:18px 0 0;font-size:13px;color:var(--ink2);line-height:1.55}
.trust{display:flex;flex-wrap:wrap;justify-content:center;gap:6px 20px;margin-top:14px;font-size:13px;color:var(--muted)}
.trust span{display:inline-flex;align-items:center;gap:6px}
.trust i{font-style:normal;color:#16a34a;display:inline-flex}

main{flex:1;width:100%;max-width:1040px;margin:0 auto;padding:0 20px 56px}
#out{scroll-margin-top:76px}
.label{font-size:12px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin:0 0 14px}
.home{padding-top:8px}
.cves{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.cve{border:1px solid var(--line);border-radius:16px;padding:20px 22px;background:#fff;box-shadow:var(--shadow)}
.cve-top{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:12px}
.cve-id{font:700 13px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:#b91c1c;background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:3px 9px}
.sev{font-size:12px;font-weight:700;color:#b91c1c}
.cve h3{margin:0 0 6px;font-size:18px;letter-spacing:-.02em}
.cve p{margin:0 0 14px;color:var(--ink2)}
.tags{display:flex;flex-wrap:wrap;gap:6px}
.tags span{font-size:12px;font-weight:600;color:var(--ink2);background:var(--soft);border:1px solid var(--line);border-radius:999px;padding:2px 10px}
.range{display:flex;flex-wrap:wrap;align-items:center;gap:10px 28px;margin-top:16px;padding:14px 20px;border:1px solid var(--line);border-radius:14px;background:var(--soft)}
.range .k{font-size:12px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-right:10px}
.range b{font-weight:700}
.fx{display:inline-block;font-weight:700;font-size:13px;color:#15803d;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:1px 9px;margin-right:6px}
.steps{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-top:36px}
.step{display:flex;gap:14px}
.step .n{flex:none;width:32px;height:32px;border-radius:50%;background:var(--accent-soft);color:var(--accent);font-weight:800;display:grid;place-items:center}
.step b{display:block;margin-bottom:2px}
.step span{color:var(--muted);font-size:14px}

body[data-mode=results] .hero{padding:30px 20px 24px}
body[data-mode=results] .sub,body[data-mode=results] .trust,body[data-mode=results] .home,body[data-mode=results] .consent{display:none}
body[data-mode=results] .title{font-size:clamp(18px,3vw,28px);margin-bottom:18px}

.vcard{--tone:#475569;--tone-soft:#f8fafc;--tone-line:#e2e8f0;border:1px solid var(--line);border-radius:18px;background:#fff;box-shadow:var(--shadow);overflow:hidden}
.vcard.vulnerable{--tone:#dc2626;--tone-soft:#fef2f2;--tone-line:#fecaca}
.vcard.verify{--tone:#b45309;--tone-soft:#fffbeb;--tone-line:#fde68a}
.vcard.patched{--tone:#15803d;--tone-soft:#f0fdf4;--tone-line:#bbf7d0}
.vhead{display:flex;gap:18px;align-items:flex-start;padding:22px 24px;background:var(--tone-soft);border-bottom:1px solid var(--tone-line)}
.vicon{flex:none;width:54px;height:54px;border-radius:15px;background:var(--tone);color:#fff;display:grid;place-items:center}
.vmain{flex:1;min-width:0}
.pill{display:inline-block;font-size:12px;font-weight:800;letter-spacing:.05em;text-transform:uppercase;color:var(--tone);border:1px solid var(--tone);border-radius:999px;padding:1px 10px;background:#fff}
.vmain h2{font-size:26px;line-height:1.2;letter-spacing:-.025em;margin:8px 0 6px}
.vmain p{margin:0;color:var(--ink2)}
.dbtn{flex:none;display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);background:#fff;border-radius:10px;padding:6px 12px;font-size:13px;font-weight:600;color:var(--ink);cursor:pointer}
.dbtn:hover{background:var(--soft)}
.dbtn .ic{transition:transform .15s}
.dbtn[aria-expanded=true] .ic{transform:rotate(180deg)}
.vbody{padding:18px 24px 18px}
.xcheck{margin-top:14px;border:1px solid var(--line);border-radius:12px;background:#fff;overflow:hidden}
.xh{display:flex;flex-wrap:wrap;gap:4px 10px;align-items:baseline;padding:10px 14px;border-bottom:1px solid var(--line);background:var(--soft);font-size:13px}
.xh span{color:var(--muted)}
.crow{display:flex;gap:12px;padding:14px;border-bottom:1px solid var(--line)}
.cnum{flex:none;width:24px;height:24px;border-radius:50%;background:var(--accent-soft);color:var(--accent);font-weight:800;font-size:12px;display:grid;place-items:center;margin-top:1px}
.cbody{flex:1;min-width:0}.cname{font-weight:700}.chow{font-size:12px;color:var(--muted);margin-bottom:4px}.cdet{font-size:14px;color:var(--ink2)}
.cres{flex:none;display:flex;flex-direction:column;align-items:flex-end;gap:4px;text-align:right}
.oc{font-size:12px;font-weight:700;border-radius:999px;padding:2px 10px;border:1px solid;white-space:nowrap}
.oc.positive{color:#b91c1c;background:#fef2f2;border-color:#fecaca}.oc.negative{color:#15803d;background:#f0fdf4;border-color:#bbf7d0}.oc.inconclusive{color:#475569;background:#f1f5f9;border-color:#e2e8f0}
.xfoot{padding:12px 14px;display:grid;gap:8px;font-size:13px}
.xlab{font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-right:8px}
.xfinal{display:flex;flex-wrap:wrap;align-items:center;gap:6px 8px}.xwhy{color:var(--ink2)}
.xcheck.positive .xfoot{background:#fef2f2}.xcheck.negative .xfoot{background:#f0fdf4}.xcheck.inconclusive .xfoot{background:var(--soft)}
@media (max-width:600px){.crow{flex-wrap:wrap}.cres{flex-direction:row;align-items:center;margin-left:36px}}
.vrow{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;margin-bottom:14px}
.target{flex:1;min-width:0;font-size:13px;color:var(--muted);margin:5px 0 0;word-break:break-all}
.target b{color:var(--ink2)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px}
.tile{background:var(--soft);border:1px solid var(--line);border-radius:12px;padding:10px 14px}
.tile .k{font-size:11px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--muted)}
.tile .v{font-weight:700;font-size:15px;word-break:break-word}
.checked{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-top:16px;font-size:13px;color:var(--muted)}
.chip{font:600 12px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:var(--ink2);background:var(--soft);border:1px solid var(--line);border-radius:8px;padding:2px 9px}
.notes{display:grid;gap:10px;margin-top:18px;padding-top:16px;border-top:1px solid var(--line)}
.nt{display:flex;gap:10px;font-size:14px;color:var(--ink2)}
.nt .ic{flex:none;color:var(--accent);margin-top:2px}
.nt b{display:block;color:var(--ink)}
.details{margin-top:18px;padding-top:6px;border-top:1px solid var(--line)}
.details h4{margin:14px 0 6px;font-size:12px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--muted)}
dl{display:grid;grid-template-columns:150px 1fr;gap:5px 14px;margin:0;font-size:14px}
dt{color:var(--muted)}dd{margin:0;word-break:break-word}
.checks{list-style:none;margin:6px 0 0;padding:0}
.chk{display:flex;gap:12px;padding:9px 0;border-top:1px solid var(--line)}
.chk:first-child{border-top:0}
.dot{flex:none;width:22px;height:22px;border-radius:50%;display:grid;place-items:center;font-size:12px;font-weight:800;color:#64748b;background:#f1f5f9}
.chk.found .dot,.chk.ok .dot{background:#dcfce7;color:#15803d}
.chk b{display:block;font-size:14px}
.cn{color:var(--muted);font-size:13px;word-break:break-word}
.logged{margin-top:16px;color:var(--muted);font-size:12px}

.sec{display:flex;align-items:baseline;justify-content:space-between;gap:12px;margin:40px 0 12px}
.sec h2{margin:0;font-size:21px;letter-spacing:-.025em}
.sec span{color:var(--muted);font-size:14px}
details.guide{border:1px solid var(--line);border-radius:14px;background:#fff;margin:10px 0;box-shadow:0 1px 2px rgba(15,23,42,.04)}
details.guide[open]{box-shadow:var(--shadow)}
details.guide>summary{display:flex;gap:14px;align-items:flex-start;padding:15px 16px;cursor:pointer;list-style:none}
details.guide>summary::-webkit-details-marker{display:none}
.num{flex:none;width:30px;height:30px;border-radius:50%;background:var(--accent-soft);color:var(--accent);font-weight:800;font-size:13px;display:grid;place-items:center}
.gm{flex:1;min-width:0}
.gt{font-weight:700;font-size:16px;line-height:1.35}
.gs{color:var(--muted);font-size:14px}
.rec{display:inline-block;margin-left:8px;font-size:11px;font-weight:700;color:#15803d;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:999px;padding:0 8px;vertical-align:middle}
.chev{flex:none;color:var(--muted);margin-top:4px;transition:transform .15s}
details[open]>summary .chev{transform:rotate(180deg)}
.gb{padding:2px 18px 16px 60px}
.gb h4{margin:14px 0 4px;font-size:12px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--muted)}
.gb p{margin:8px 0;color:var(--ink2)}
.codewrap{position:relative}
pre{margin:8px 0;padding:14px 16px;overflow-x:auto;border-radius:10px;background:#0f172a;color:#e2e8f0;font:12.5px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.copy{position:absolute;top:8px;right:8px;font-size:11px;font-weight:600;padding:3px 9px;border:1px solid #334155;border-radius:6px;background:#1e293b;color:#cbd5e1;cursor:pointer}
.copy:hover{background:#334155}
details.more{margin:14px 0}
details.more>summary{display:inline-flex;align-items:center;gap:6px;cursor:pointer;list-style:none;color:var(--accent);font-weight:600;font-size:14px}
details.more>summary::-webkit-details-marker{display:none}
details.more>summary .ic{transition:transform .15s}
details.more[open]>summary .ic{transform:rotate(180deg)}
details.more>div{margin-top:8px}
.refs{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.ref{display:block;border:1px solid var(--line);border-radius:12px;padding:12px 14px;background:#fff;color:inherit}
.ref:hover{border-color:var(--accent-line);box-shadow:var(--shadow);text-decoration:none}
.ref .rt{font-weight:600;color:var(--ink);line-height:1.35}
.ref .rd{font-size:12px;color:var(--muted);margin:1px 0 3px}
.ref .rs{font-size:13px;color:var(--muted);display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.busy{display:flex;align-items:center;gap:14px;border:1px solid var(--line);border-radius:16px;padding:22px 24px;background:#fff;box-shadow:var(--shadow)}
.spin{flex:none;width:26px;height:26px;border:3px solid var(--accent-line);border-top-color:var(--accent);border-radius:50%;animation:s .9s linear infinite}
@keyframes s{to{transform:rotate(360deg)}}

footer{border-top:1px solid var(--line);background:var(--soft);color:var(--muted);font-size:13px}
footer .wrap{display:flex;flex-wrap:wrap;gap:6px 24px;justify-content:space-between;padding-top:18px;padding-bottom:18px}
footer b{color:var(--ink2);font-weight:600}

@media (max-width:760px){
  .hero{padding:44px 16px 28px}
  .title{font-size:min(30px,4.6vw)}
  .sub{font-size:15px}
  .cves,.refs,.steps{grid-template-columns:1fr}
  .search{padding-left:12px}.btn{padding:0 16px}
  .vhead{padding:18px;gap:14px}.vicon{width:44px;height:44px}.vmain h2{font-size:21px}
  .vbody{padding:16px 18px}
  dl{grid-template-columns:1fr;gap:0 0}dt{margin-top:8px}
  .gb{padding-left:18px}
}
@media (max-width:480px){.btn .t{display:none}.sub{font-size:14px}.wrap,main{padding-left:16px;padding-right:16px}.ghbtn span.t{display:none}}
</style>
</head>
<body data-mode="home">
<header class="top"><div class="wrap">
  <a class="brand" href="/" aria-label="PHPChecker home"><svg width="28" height="28" viewBox="0 0 24 24" aria-hidden="true"><path fill="#4f46e5" d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5z"/><path d="m8.5 12 2.5 2.5 4.5-5" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>PHPChecker</a>
  <a class="ghbtn" href="__REPO__" target="_blank" rel="noopener noreferrer"><span class="ic">__I_GITHUB__</span><span class="t">GitHub</span></a>
</div></header>
<section class="hero" id="hero">
  <h1 class="title">Is your PHP website exposed to php2shell?</h1>
  <p class="sub">Scanner for CVE-2026-109618 and CVE-2026-109619.</p>
  <form id="form" autocomplete="off">
    <div class="search">
      <span class="ic">__I_GLOBE__</span>
      <input id="q" name="q" type="text" inputmode="url" spellcheck="false" autocapitalize="off" placeholder="Enter your website URL" aria-label="Website URL" autofocus>
      <button class="btn" id="go" type="submit">Scan<span class="t"> website</span> <span class="ic">__I_ARROW__</span></button>
    </div>
    <p class="consent"><b>By scanning you confirm you own this site or are authorised to test it.</b><br><b>Passive check only &ndash; nothing is exploited.</b></p>
    <div class="trust"><span><i class="ic">__I_CHECK__</i>Normal requests only</span><span><i class="ic">__I_CHECK__</i>Nothing exploited</span><span><i class="ic">__I_CHECK__</i>No cookies or tracking</span></div>
  </form>
</section>
<main id="main">
  <div id="out" aria-live="polite"></div>
  __HOME__
</main>
<footer><div class="wrap">
  <span><b>Open source</b> (MIT) &middot; <a href="__REPO__" target="_blank" rel="noopener noreferrer">source on GitHub</a> &middot; fallback method from <a href="https://github.com/openai/php2shell-checker" target="_blank" rel="noopener noreferrer">OpenAI php2shell-checker</a> (Apache-2.0)</span>
  <span>No cookies, analytics or tracking. Only scan requests are logged, for safety and audit-trail purposes.</span>
</div></footer>
<script nonce="__NONCE__">
(function(){
var ICONS=__ICONS__;
var $=function(s){return document.querySelector(s)};
var out=$('#out'),input=$('#q'),go=$('#go');
var state={items:[],context:[],result:null},resPromise=null,seq=0;

function svg(n,sz){return '<svg viewBox="0 0 24 24" width="'+sz+'" height="'+sz+'" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'+ICONS[n]+'</svg>';}
function icon(n,sz){var s=document.createElement('span');s.className='ic';s.innerHTML=svg(n,sz||18);return s;} /* constant icons only */
function h(tag,attrs){
  var el=document.createElement(tag),i,c,k;
  if(attrs)for(k in attrs){if(k==='class')el.className=attrs[k];else if(k==='text')el.textContent=attrs[k];else el.setAttribute(k,attrs[k]);}
  for(i=2;i<arguments.length;i++){c=arguments[i];if(c==null||c===false)continue;el.appendChild(typeof c==='string'?document.createTextNode(c):c);}
  return el;
}
function clear(el){while(el.firstChild)el.removeChild(el.firstChild);}
function setMode(m){document.body.setAttribute('data-mode',m);}

function loadResources(){
  if(!resPromise)resPromise=fetch('/api/resources').then(function(r){if(!r.ok)throw new Error('resources');return r.json();})
    .then(function(d){state.items=d.items;return d;})
    .catch(function(){resPromise=null;return null;}); /* retry next scan; the result still renders */
  return resPromise;
}

function run(q){
  q=q.trim();if(!q)return;
  var mine=++seq; /* ignore responses from older, superseded scans */
  setMode('results');go.disabled=true;
  clear(out);out.appendChild(h('div',{class:'busy',role:'status'},h('div',{class:'spin'}),h('div',null,h('b',{text:'Scanning '+q.replace(/^https?:\/\//i,'').slice(0,80)+'…'}),h('div',{class:'cn',text:'Making one normal request and reading the response headers.'}))));
  history.pushState({},'','?q='+encodeURIComponent(q));
  var api='/api/scan?authorized=1&url='+encodeURIComponent(q);
  Promise.all([fetch(api).then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};});}),loadResources()]).then(function(a){
    if(mine!==seq)return;
    go.disabled=false;
    if(!a[0].ok){showError(a[0].j.message||'Request failed.');return;}
    state.result=a[0].j;state.context=a[0].j.context||[];render();
    out.scrollIntoView({behavior:'smooth',block:'start'});
  }).catch(function(){if(mine===seq){go.disabled=false;showError('Could not reach the PHPChecker service.');}});
}

function showError(msg){
  clear(out);
  out.appendChild(h('section',{class:'vcard error',role:'alert'},h('div',{class:'vhead'},h('div',{class:'vicon'},icon('shieldQ',28)),h('div',{class:'vmain'},h('span',{class:'pill',text:'Could not scan'}),h('h2',{text:msg})))));
}

function tile(parent,k,v){if(v==null||v==='')return;parent.appendChild(h('div',{class:'tile'},h('div',{class:'k',text:k}),h('div',{class:'v',text:v})));}
function fact(dl,k,v){if(v==null||v==='')return;dl.appendChild(h('dt',{text:k}));dl.appendChild(h('dd',{text:v}));}

var PILL={vulnerable:'Action needed',verify:'Check required',patched:'Safe version','no-php':'Not detected',unknown:'Inconclusive'};
var VICON={vulnerable:'shieldAlert',verify:'shieldQ',patched:'shieldCheck','no-php':'shieldQ',unknown:'shieldQ'};

var OUT={positive:'Positive',negative:'Negative',inconclusive:'Inconclusive'};
function checkRow(c,n){
  return h('div',{class:'crow'},
    h('span',{class:'cnum',text:String(n)}),
    h('div',{class:'cbody'},h('div',{class:'cname',text:c.name.replace(/^Check \d · /,'')}),h('div',{class:'chow',text:c.how||''}),h('div',{class:'cdet',text:c.detail})),
    h('div',{class:'cres'},h('span',{class:'oc '+c.outcome,text:OUT[c.outcome]}),c.version?h('b',{text:'PHP '+c.version}):null));
}
function crossCheck(r){
  var c=r.crossCheck;if(!c)return null;
  return h('div',{class:'xcheck '+c.final},
    h('div',{class:'xh'},h('b',{text:'How this result was reached'}),h('span',{text:'two independent checks, combined by a fixed rule'})),
    checkRow(c.checks[0],1),checkRow(c.checks[1],2),
    h('div',{class:'xfoot'},h('div',{class:'xrule'},h('span',{class:'xlab',text:'Rule'}),h('span',{text:'Positive if either check is positive. Negative only if both are negative. Otherwise inconclusive.'})),
      h('div',{class:'xfinal'},h('span',{class:'xlab',text:'Result'}),h('span',{class:'oc '+c.final,text:OUT[c.final]}),h('span',{class:'xwhy',text:c.rule}))));
}

function verdictCard(r){
  var fp=(r.details&&r.details.fingerprint)||{},ws=fp.webserver,os=fp.os;
  var card=h('section',{class:'vcard '+r.verdict});
  var panel=detailsPanel(r);
  var dbtn=h('button',{class:'dbtn',type:'button','aria-expanded':'false'},h('span',{text:'Details'}),icon('chevron',16));
  dbtn.addEventListener('click',function(){
    var open=panel.hidden;panel.hidden=!open;dbtn.setAttribute('aria-expanded',String(open));dbtn.firstChild.textContent=open?'Hide details':'Details';
  });
  card.appendChild(h('div',{class:'vhead'},
    h('div',{class:'vicon'},icon(VICON[r.verdict]||'shieldQ',28)),
    h('div',{class:'vmain'},h('span',{class:'pill',text:PILL[r.verdict]||r.verdict}),h('h2',{text:r.headline}),h('p',{text:r.detail}))));
  var body=h('div',{class:'vbody'});
  body.appendChild(h('div',{class:'vrow'},h('p',{class:'target'},'Scanned ',h('b',{text:r.target})),dbtn));
  var tiles=h('div',{class:'tiles'});
  tile(tiles,'PHP version',r.php.version||(r.php.detected?'Not disclosed':null));
  tile(tiles,'First fixed in',r.php.fixedIn);
  tile(tiles,'Web server',ws?(ws.name+(ws.version?' '+ws.version:'')):null);
  tile(tiles,'Operating system',os?(os.name+(os.release?' '+os.release:'')):null);
  tile(tiles,'CDN / proxy',fp.cdn);
  tile(tiles,'Application',r.php.cms&&r.php.cms.length?r.php.cms.join(', '):null);
  tile(tiles,'PHP SAPI',r.php.sapi&&r.php.sapi!=='unknown'?r.php.sapi:null);
  if(tiles.firstChild)body.appendChild(tiles);
  var xc=crossCheck(r);if(xc)body.appendChild(xc);
  var checked=h('div',{class:'checked'},h('span',{text:'Checked for'}));
  (r.advisory.cves||[]).forEach(function(c){checked.appendChild(h('span',{class:'chip',text:c}));});
  body.appendChild(checked);
  if((r.findings||[]).length){
    var notes=h('div',{class:'notes'});
    r.findings.forEach(function(f){notes.appendChild(h('div',{class:'nt'},icon('info',16),h('div',null,h('b',{text:f.title}),h('span',{text:f.detail}))));});
    body.appendChild(notes);
  }
  body.appendChild(panel);
  body.appendChild(h('div',{class:'logged',text:'This scan request was logged for safety and audit-trail purposes (time, your IP address and country, browser user agent, target hostname and result). Nothing else is tracked.'}));
  card.appendChild(body);
  return card;
}

function detailsPanel(r){
  var d=r.details||{checks:[],fingerprint:{}};
  var fp=d.fingerprint||{},ws=fp.webserver,os=fp.os;
  var p=h('div',{class:'details',hidden:''});
  p.appendChild(h('h4',{text:'What we found'}));
  var dl=h('dl');
  fact(dl,'Web server',ws?(ws.name+(ws.version?' '+ws.version:''))+(ws.behindCdn?' (CDN edge – origin server not visible)':''):'Not disclosed');
  fact(dl,'Server header',ws?ws.raw:null);
  fact(dl,'PHP',fp.php&&fp.php.version?('PHP '+fp.php.version+(fp.php.banner&&fp.php.banner!==fp.php.version?' – banner "'+fp.php.banner+'"':'')):'Not disclosed');
  fact(dl,'PHP SAPI',fp.php&&fp.php.sapi&&fp.php.sapi!=='unknown'?fp.php.sapi:'Unknown');
  fact(dl,'Operating system',os?(os.name+(os.release?' '+os.release:'')+' ('+os.confidence+' confidence: '+os.basis+')'):'Could not be fingerprinted');
  fact(dl,'CDN / proxy',fp.cdn);
  if(d.request){
    fact(dl,'HTTP response',String(d.request.httpStatus)+(d.request.elapsedMs!=null?' in '+d.request.elapsedMs+' ms':'')+', '+d.request.redirects+' redirect(s)');
    fact(dl,'Connection',d.request.transportNote);
    fact(dl,'User-Agent',d.request.userAgent);
  }
  p.appendChild(dl);
  p.appendChild(h('h4',{text:'How we checked'}));
  var ul=h('ul',{class:'checks'});
  var mark={found:'✓',ok:'✓',none:'–',skipped:'○'};
  d.checks.forEach(function(c){
    ul.appendChild(h('li',{class:'chk '+c.status},h('span',{class:'dot',text:mark[c.status]||'•'}),h('div',null,h('b',{text:c.name}),h('div',{class:'cn',text:c.note}))));
  });
  p.appendChild(ul);
  p.appendChild(h('p',{class:'cn',text:'Fingerprints are hints from public banners. They can be hidden, spoofed or reflect distribution backports, so treat them as leads, not proof.'}));
  return p;
}

function score(item){
  if(!item.when||!item.when.length)return 0;
  for(var i=0;i<item.when.length;i++)if(state.context.indexOf(item.when[i])>-1)return 1;
  return -1;
}
function host(url){try{var u=new URL(url);return u.hostname+(u.pathname!=='/'?' › '+u.pathname.split('/').filter(Boolean).slice(0,2).join(' › '):'');}catch(e){return url;}}

function refLink(it){
  return h('a',{class:'ref',href:it.url,target:'_blank',rel:'noopener noreferrer'},h('div',{class:'rt',text:it.title}),h('div',{class:'rd',text:host(it.url)}),h('div',{class:'rs',text:it.snippet}));
}
function codeBlock(text){
  var pre=h('pre',null,h('code',{text:text}));
  var b=h('button',{class:'copy',type:'button',text:'Copy'});
  b.addEventListener('click',function(){
    var done=function(){b.textContent='Copied';setTimeout(function(){b.textContent='Copy';},1400);};
    try{navigator.clipboard.writeText(text).then(done,function(){});}catch(e){}
  });
  return h('div',{class:'codewrap'},b,pre);
}
function guideCard(it,n,rec,open){
  var d=h('details',{class:'guide'});
  if(open)d.setAttribute('open','');
  d.appendChild(h('summary',null,h('span',{class:'num',text:String(n)}),
    h('div',{class:'gm'},h('div',{class:'gt'},it.title,rec?h('span',{class:'rec',text:'Recommended'}):null),h('div',{class:'gs',text:it.snippet})),
    h('span',{class:'chev'},icon('chevron',18))));
  var body=h('div',{class:'gb'});
  it.sections.forEach(function(s){
    if(s.h)body.appendChild(h('h4',{text:s.h}));
    if(s.text)body.appendChild(h('p',{text:s.text.replace(/\x60/g,'')}));
    if(s.code)body.appendChild(codeBlock(s.code));
  });
  d.appendChild(body);return d;
}
function more(label,child){
  return h('details',{class:'more'},h('summary',null,h('span',{text:label}),icon('chevron',16)),h('div',null,child));
}

function render(){
  clear(out);
  out.appendChild(verdictCard(state.result));
  var scored=state.items.map(function(it,idx){return {it:it,idx:idx,s:score(it)};});
  var byRank=function(a,b){return (b.s-a.s)||(a.idx-b.idx);};
  var guides=scored.filter(function(x){return x.it.kind==='guide';}).sort(byRank);
  var links=scored.filter(function(x){return x.it.kind==='link';}).sort(byRank);
  if(!guides.length&&!links.length)return;

  var top=guides.slice(0,4),rest=guides.slice(4);
  out.appendChild(h('div',{class:'sec'},h('h2',{text:'What to do next'}),h('span',{text:'Ranked for this result'})));
  top.forEach(function(x,i){out.appendChild(guideCard(x.it,i+1,x.s>0,i===0&&x.s>0));});
  if(rest.length){
    var box=h('div');
    rest.forEach(function(x,i){box.appendChild(guideCard(x.it,top.length+i+1,x.s>0,false));});
    out.appendChild(more('Show '+rest.length+' more guides',box));
  }

  var tracker=/^(debian|ubuntu|rh|suse|alpine|amzn)-/;
  var refs=links.filter(function(x){return !tracker.test(x.it.id);}),trackers=links.filter(function(x){return tracker.test(x.it.id);});
  out.appendChild(h('div',{class:'sec'},h('h2',{text:'References and detection rules'}),h('span',{text:refs.length+' links'})));
  var grid=h('div',{class:'refs'});
  refs.forEach(function(x){grid.appendChild(refLink(x.it));});
  out.appendChild(grid);
  if(trackers.length){
    var g2=h('div',{class:'refs'});
    trackers.forEach(function(x){g2.appendChild(refLink(x.it));});
    out.appendChild(more('Distro security trackers ('+trackers.length+')',g2));
  }
}

$('#form').addEventListener('submit',function(e){e.preventDefault();run(input.value);});
window.addEventListener('popstate',function(){setMode('home');clear(out);input.value=new URLSearchParams(location.search).get('q')||'';});
var q0=new URLSearchParams(location.search).get('q');
if(q0)input.value=q0; /* prefill only: never auto-scan from a link */
})();
</script>
</body>
</html>`;

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const severity = (n) => (n >= 9 ? 'Critical' : n >= 7 ? 'High' : n >= 4 ? 'Medium' : 'Low');

const fixedChips = Object.entries(ADVISORY.fixed)
  .map(([b, p]) => `<span class="fx">${esc(b)}.${esc(p)}</span>`)
  .join('');

const HOME_HTML =
  '<section class="home" aria-label="What this app scans for">' +
  '<h2 class="label">This app scans websites for</h2>' +
  '<div class="cves">' +
  ADVISORY.cves
    .map(
      (c) =>
        `<article class="cve"><div class="cve-top"><span class="cve-id">${esc(c.id)}</span><span class="sev">CVSS ${esc(c.cvss)} &middot; ${severity(c.cvss)}</span></div>` +
        `<h3>${esc(c.title)}</h3><p>${esc(c.description)}</p>` +
        '<div class="tags"><span>Unauthenticated</span><span>Remote</span><span>Code execution</span></div></article>',
    )
    .join('') +
  '</div>' +
  `<div class="range"><div><span class="k">Affected</span><b>PHP 5.4.0 &ndash; ${esc(ADVISORY.lastAffected)}</b></div><div><span class="k">Fixed in</span>${fixedChips}</div></div>` +
  '<div class="steps">' +
  '<div class="step"><span class="n">1</span><div><b>Fetch</b><span>A normal page request to your site &ndash; never an exploit.</span></div></div>' +
  '<div class="step"><span class="n">2</span><div><b>Fingerprint</b><span>PHP version, web server, OS hint, CDN and CMS. If the version is hidden, a HEAD check using OpenAI&rsquo;s method.</span></div></div>' +
  '<div class="step"><span class="n">3</span><div><b>Compare</b><span>Against the advisory&rsquo;s affected range and fixed releases. A hidden version is reported as unknown, not safe.</span></div></div>' +
  '</div></section>';

const STATIC_PAGE = PAGE.replace('__HOME__', HOME_HTML)
  .replace('__ICONS__', JSON.stringify(ICON_PATHS))
  .replace('__I_GITHUB__', svg('github', 18))
  .replace('__I_GLOBE__', svg('globe', 20))
  .replace('__I_ARROW__', svg('arrow', 18))
  .replaceAll('__I_CHECK__', svg('check', 14))
  .replaceAll('__REPO__', esc(PROJECT.repo));

export function renderPage(nonce) {
  return STATIC_PAGE.replaceAll('__NONCE__', nonce);
}
