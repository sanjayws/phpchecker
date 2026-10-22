import { ADVISORY } from './advisory.js';
import { PROJECT } from './project.js';

// The whole front end as one string so the Worker stays a single deployable file set.
// Client code avoids template literals so it can live inside this one. All dynamic text
// is inserted with textContent / createTextNode – never innerHTML.

const PAGE = String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PHPChecker – php2shell CVE scanner</title>
<meta name="description" content="Open-source scanner that checks websites for the php2shell PHP vulnerabilities CVE-2026-109618 and CVE-2026-109619, with fixes, workarounds and detection help.">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Ccircle cx='14' cy='14' r='9' fill='none' stroke='%231a73e8' stroke-width='4'/%3E%3Cpath d='M21 21l8 8' stroke='%231a73e8' stroke-width='4' stroke-linecap='round'/%3E%3C/svg%3E">
<style nonce="__NONCE__">
:root{--bg:#fff;--fg:#202124;--muted:#5f6368;--line:#dfe1e5;--link:#1a0dab;--crumb:#188038;--blue:#4285f4;--red:#ea4335;--yellow:#fbbc05;--green:#34a853;--card:#fff;--code:#f1f3f4;--shadow:0 1px 6px rgba(32,33,36,.28);--ok:#188038;--bad:#d93025;--warn:#b06000;--idle:#5f6368}
@media (prefers-color-scheme:dark){:root{--bg:#202124;--fg:#e8eaed;--muted:#9aa0a6;--line:#3c4043;--link:#8ab4f8;--crumb:#81c995;--card:#292a2d;--code:#171717;--shadow:0 1px 6px rgba(0,0,0,.6);--ok:#81c995;--bad:#f28b82;--warn:#fdd663;--idle:#9aa0a6}}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--bg);color:var(--fg);font:14px/1.58 Arial,"Helvetica Neue",Helvetica,sans-serif;min-height:100vh;display:flex;flex-direction:column}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
button{font:inherit}
.hero{display:flex;flex-direction:column;align-items:center;margin-top:20vh;padding:0 16px}
.logo{font-size:68px;font-weight:500;letter-spacing:-2px;line-height:1;user-select:none;margin:0 0 26px;font-family:"Product Sans","Google Sans",Arial,sans-serif}
.logo a{color:inherit;text-decoration:none}
.logo span:nth-child(6n+1),.logo span:nth-child(6n+4){color:var(--blue)}
.logo span:nth-child(6n+2),.logo span:nth-child(6n){color:var(--red)}
.logo span:nth-child(6n+3){color:var(--yellow)}
.logo span:nth-child(6n+5){color:var(--green)}
form{width:100%;max-width:584px}
.box{display:flex;align-items:center;gap:12px;height:46px;padding:0 18px;border:1px solid var(--line);border-radius:24px;background:var(--card)}
.box:hover,.box:focus-within{box-shadow:var(--shadow);border-color:transparent}
.box svg{flex:none;fill:var(--muted)}
.box input{flex:1;min-width:0;height:100%;border:0;outline:0;background:transparent;color:var(--fg);font:16px Arial,sans-serif}
.note{margin:16px 8px 0;text-align:center;color:var(--muted);font-size:12px}
.cves{width:100%;max-width:584px;margin:30px 0 0;font-size:13px;color:var(--muted)}
.cves h2{font-size:13px;font-weight:700;color:var(--fg);margin:0 0 6px;text-transform:uppercase;letter-spacing:.5px}
.cves ul{margin:0;padding-left:18px}.cves li{margin:4px 0}
.cves p{margin:8px 0 0}
footer b{color:var(--fg);font-weight:600}
.actions{display:flex;gap:12px;justify-content:center;margin-top:24px}
.btn{background:var(--code);color:var(--fg);border:1px solid var(--code);border-radius:4px;padding:0 16px;height:36px;cursor:pointer}
.btn:hover{border-color:var(--line);box-shadow:0 1px 1px rgba(0,0,0,.1)}
main{flex:1;width:100%;max-width:780px;margin:0 auto;padding:0 16px 40px}
[hidden]{display:none!important}
body[data-mode=results] .hero{margin-top:7vh}
body[data-mode=results] .cves{display:none}
body[data-mode=results] main{margin-top:28px}
.stats{color:var(--muted);font-size:13px;margin:16px 0 8px}
.card{background:var(--card);border:1px solid var(--line);border-left-width:6px;border-radius:8px;padding:16px 20px;margin:12px 0 8px}
.card.vulnerable{border-left-color:var(--bad)}.card.verify{border-left-color:var(--yellow)}.card.patched{border-left-color:var(--ok)}.card.unknown,.card.no-php,.card.error{border-left-color:var(--idle)}
.pill{display:inline-block;font-size:12px;font-weight:700;letter-spacing:.4px;text-transform:uppercase;padding:2px 10px;border-radius:12px;border:1px solid currentColor}
.vulnerable .pill{color:var(--bad)}.verify .pill{color:var(--warn)}.patched .pill{color:var(--ok)}.unknown .pill,.no-php .pill,.error .pill{color:var(--idle)}
.card h2{font-size:22px;font-weight:400;margin:10px 0 6px}
.card p{margin:0 0 10px}
dl{display:grid;grid-template-columns:130px 1fr;gap:4px 12px;margin:10px 0 0}
dt{color:var(--muted)}dd{margin:0;word-break:break-word}
.cardtop{display:flex;align-items:center;justify-content:space-between}
.dbtn{background:none;border:1px solid var(--line);color:var(--link);border-radius:14px;padding:1px 12px;font-size:12px;cursor:pointer}
.dbtn:hover{background:var(--code)}
.details{border-top:1px solid var(--line);margin-top:14px;padding-top:4px}
.details h4{margin:12px 0 2px;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.4px}
.checks{list-style:none;margin:6px 0;padding:0}
.chk{display:flex;gap:10px;margin:8px 0}
.chk .ico{flex:none;width:18px;text-align:center;color:var(--idle)}
.chk.found .ico,.chk.ok .ico{color:var(--ok)}
.cn{color:var(--muted);font-size:13px;word-break:break-word}
.logged{margin-top:14px;color:var(--muted);font-size:12px}
.find{border-top:1px solid var(--line);margin-top:12px;padding-top:10px}
.find b{display:block}.find span{color:var(--muted)}
h3.sec{font-size:18px;font-weight:400;margin:26px 0 4px}
.res{margin:18px 0}
.crumb{color:var(--crumb);font-size:12px;line-height:1.3;word-break:break-all}
.res a.t{font-size:19px;line-height:1.3;display:inline-block;margin:2px 0}
.res p{margin:2px 0 0;color:var(--muted)}
.rel{display:inline-block;margin-left:8px;font-size:11px;color:var(--ok);border:1px solid var(--ok);border-radius:10px;padding:0 7px;vertical-align:middle}
details.guide{border:1px solid var(--line);border-radius:8px;margin:14px 0;background:var(--card)}
details.guide summary{cursor:pointer;padding:12px 16px;list-style:none}
details.guide summary::-webkit-details-marker{display:none}
details.guide summary .g{font-size:17px;color:var(--link)}
details.guide summary p{margin:2px 0 0;color:var(--muted)}
details.guide[open] summary{border-bottom:1px solid var(--line)}
.gb{padding:6px 16px 14px}
.gb h4{margin:14px 0 4px;font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.4px}
.gb p{margin:8px 0}
.codewrap{position:relative}
pre{background:var(--code);border-radius:6px;padding:12px 14px;overflow-x:auto;font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;margin:8px 0}
.copy{position:absolute;top:6px;right:6px;font-size:11px;padding:2px 8px;border:1px solid var(--line);border-radius:4px;background:var(--card);color:var(--muted);cursor:pointer}
.spin{margin:48px auto;width:28px;height:28px;border:3px solid var(--line);border-top-color:var(--blue);border-radius:50%;animation:s 1s linear infinite}
@keyframes s{to{transform:rotate(360deg)}}
footer{border-top:1px solid var(--line);background:var(--code);color:var(--muted);padding:14px 24px;font-size:13px;display:flex;flex-wrap:wrap;gap:6px 24px;justify-content:space-between}
@media (max-width:600px){.logo{font-size:48px}dl{grid-template-columns:1fr}}
</style>
</head>
<body data-mode="home">
<div class="hero" id="hero">
  <h1 class="logo"><a href="/" aria-label="PHPChecker home"><span>p</span><span>h</span><span>p</span><span>c</span><span>h</span><span>e</span><span>c</span><span>k</span><span>e</span><span>r</span></a></h1>
  <form id="form" autocomplete="off">
    <label class="box">
      <svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true"><path d="M15.5 14h-.79l-.28-.27A6.47 6.47 0 0 0 16 9.5 6.5 6.5 0 1 0 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg>
      <input id="q" name="q" type="text" inputmode="url" spellcheck="false" autocapitalize="off" placeholder="Enter a website URL to scan" aria-label="Website URL" autofocus>
    </label>
    <div class="actions"><button class="btn" type="submit">Scan</button></div>
    <p class="note"><b>By scanning you confirm you own this site or are authorised to test it.</b><br><b>Passive check only &ndash; nothing is exploited.</b></p>
  </form>
  __CVES__
</div>
<main id="main">
  <div id="out" aria-live="polite"></div>
</main>
<footer><span><b>Open source</b> (MIT) &middot; <a href="__REPO__" target="_blank" rel="noopener noreferrer">source on GitHub</a> &middot; No cookies, analytics or tracking. Only scan requests are logged, for safety and audit-trail purposes.</span><span>Advisory data: <a href="https://github.com/ikow/php2shell-poc" target="_blank" rel="noopener noreferrer">ikow/php2shell-poc</a> and linked advisories &middot; verify against php.net</span></footer>
<script nonce="__NONCE__">
(function(){
var $=function(s){return document.querySelector(s)};
var out=$('#out'),input=$('#q');
var state={res:null,items:[],context:[],result:null};
var resPromise=null;

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
    .then(function(d){state.res=d;state.items=d.items;return d;})
    .catch(function(){resPromise=null;return null;}); /* retry next scan; result still renders */
  return resPromise;
}
var seq=0;

function run(q,push){
  q=q.trim();if(!q)return;
  setMode('results');
  clear(out);out.appendChild(h('div',{class:'spin',role:'status','aria-label':'Scanning'}));
  if(push)history.pushState({},'','?q='+encodeURIComponent(q));
  var api='/api/scan?authorized=1&url='+encodeURIComponent(q);
  var mine=++seq; /* ignore responses from older, superseded scans */
  Promise.all([fetch(api).then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};});}),loadResources()]).then(function(a){
    if(mine!==seq)return;
    if(!a[0].ok){showError(a[0].j.message||'Request failed.');return;}
    state.result=a[0].j;state.context=a[0].j.context||[];render();
  }).catch(function(){if(mine===seq)showError('Could not reach the PHPChecker service.');});
}

function showError(msg){
  clear(out);
  out.appendChild(h('div',{class:'card error',role:'alert'},h('span',{class:'pill',text:'Problem'}),h('h2',{text:msg})));
}

function fact(dl,k,v){if(v==null||v==='')return;dl.appendChild(h('dt',{text:k}));dl.appendChild(h('dd',{text:v}));}

function verdictCard(r){
  var card=h('section',{class:'card '+r.verdict});
  var top=h('div',{class:'cardtop'},h('span',{class:'pill',text:r.verdict==='no-php'?'No PHP found':r.verdict}));
  var panel=detailsPanel(r);
  var dbtn=h('button',{class:'dbtn',type:'button','aria-expanded':'false',text:'Details'});
  dbtn.addEventListener('click',function(){
    var open=panel.hidden;panel.hidden=!open;dbtn.setAttribute('aria-expanded',String(open));dbtn.textContent=open?'Hide details':'Details';
  });
  top.appendChild(dbtn);card.appendChild(top);
  card.appendChild(h('h2',{text:r.headline}));
  card.appendChild(h('p',{text:r.detail}));
  var dl=h('dl');
  fact(dl,'Target',r.target);
  fact(dl,'PHP version',r.php.version);
  fact(dl,'First fixed',r.php.fixedIn);
  fact(dl,'SAPI',r.php.sapi&&r.php.sapi!=='unknown'?r.php.sapi:null);
  fact(dl,'Build',r.php.distro?'Repackaged ('+r.php.distro+') – check changelog':null);
  fact(dl,'Application',r.php.cms&&r.php.cms.length?r.php.cms.join(', '):null);
  fact(dl,'Evidence',r.php.evidence&&r.php.evidence.length?r.php.evidence.join(' · '):null);
  fact(dl,'Checked for',(r.advisory.cves||[]).join(', '));
  card.appendChild(dl);
  (r.findings||[]).forEach(function(f){card.appendChild(h('div',{class:'find'},h('b',{text:f.title}),h('span',{text:f.detail})));});
  card.appendChild(panel);
  card.appendChild(h('div',{class:'logged',text:'This scan request was logged for safety and audit-trail purposes (time, your IP address and country, browser user agent, target hostname and result). Nothing else is tracked.'}));
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
  var icon={found:'✔',ok:'✔',none:'–',skipped:'○'};
  d.checks.forEach(function(c){
    ul.appendChild(h('li',{class:'chk '+c.status},h('span',{class:'ico',text:icon[c.status]||'•'}),h('div',null,h('b',{text:c.name}),h('div',{class:'cn',text:c.note}))));
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
function host(url){try{var u=new URL(url);return u.hostname+(u.pathname!=='/'?' › '+u.pathname.split('/').filter(Boolean).slice(0,3).join(' › '):'');}catch(e){return url;}}

function linkItem(it,rel){
  var t=h('a',{class:'t',href:it.url,target:'_blank',rel:'noopener noreferrer',text:it.title});
  return h('div',{class:'res'},h('div',{class:'crumb',text:host(it.url)}),h('div',null,t,rel?h('span',{class:'rel',text:'relevant to your result'}):null),h('p',{text:it.snippet}));
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
function guideItem(it,rel){
  var d=h('details',{class:'guide'});
  d.appendChild(h('summary',null,h('span',{class:'g',text:it.title}),rel?h('span',{class:'rel',text:'relevant to your result'}):null,h('p',{text:it.snippet})));
  var body=h('div',{class:'gb'});
  it.sections.forEach(function(s){
    if(s.h)body.appendChild(h('h4',{text:s.h}));
    if(s.text)body.appendChild(h('p',{text:s.text.replace(/\x60/g,'')}));
    if(s.code)body.appendChild(codeBlock(s.code));
  });
  d.appendChild(body);return d;
}

function render(){
  clear(out);
  var r=state.result;out.appendChild(verdictCard(r));
  var items=state.items.map(function(it,idx){return {it:it,idx:idx,s:score(it)};})
    .sort(function(a,b){return (b.s-a.s)||(a.it.kind===b.it.kind?0:(a.it.kind==='guide'?-1:1))||(a.idx-b.idx);});
  if(!items.length)return;
  out.appendChild(h('h3',{class:'sec',text:'Help for this result'}));
  out.appendChild(h('div',{class:'stats',text:items.length+' resources, most relevant first: fixes, workarounds, detection and advisories'}));
  items.forEach(function(x){out.appendChild(x.it.kind==='guide'?guideItem(x.it,x.s>0):linkItem(x.it,x.s>0));});
}

$('#form').addEventListener('submit',function(e){e.preventDefault();run(input.value,true);});
window.addEventListener('popstate',function(){setMode('home');clear(out);input.value=new URLSearchParams(location.search).get('q')||'';});
var q0=new URLSearchParams(location.search).get('q');
if(q0)input.value=q0; /* prefill only: never auto-scan from a link */
})();
</script>
</body>
</html>`;

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

const fixedList = Object.entries(ADVISORY.fixed).map(([b, p]) => `${b}.${p}`).join(', ');
const CVES_HTML =
  '<section class="cves" aria-labelledby="cves-h"><h2 id="cves-h">This app scans websites for</h2><ul>' +
  ADVISORY.cves
    .map((c) => `<li><a href="https://www.cve.org/CVERecord?id=${esc(c.id)}" target="_blank" rel="noopener noreferrer"><b>${esc(c.id)}</b></a>: ${esc(c.description)}</li>`)
    .join('') +
  `</ul><p>How: ${esc(PROJECT.name)} reads the PHP version a site discloses and compares it with the affected range ` +
  `(PHP 5.4.0 &ndash; ${esc(ADVISORY.lastAffected)}; fixed in ${esc(fixedList)}). Sites that hide their version are reported as &ldquo;unknown&rdquo;, not safe.</p></section>`;

const STATIC_PAGE = PAGE.replace('__CVES__', CVES_HTML).replaceAll('__REPO__', esc(PROJECT.repo));

export function renderPage(nonce) {
  return STATIC_PAGE.replaceAll('__NONCE__', nonce);
}
