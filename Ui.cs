using System.Text;

namespace V3Guard;

/// <summary>
/// Dashboard page. The application itself is a compiled Svelte bundle built
/// from SvelteProject and embedded as /app.js + /app.css (served by
/// Dashboard.EmbeddedResource). This shell just mounts it and hands over the
/// session token; the token is lowercase hex so it is safe to inline.
/// </summary>
public static class Ui
{
    public static string Html(string token)
    {
        string t = token ?? "";
        return $$"""
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>NPav RDP Protection</title>
<link rel="icon" href="/@1.ico">
<link rel="stylesheet" href="/app.css">
<script>window.GUARD_TOKEN='{{t}}';</script>
</head><body>
<div id="app"></div>
<script src="/app.js"></script>
</body></html>
""";
    }

    public static string ActivationHtml(string token)
    {
        return $$"""
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>NPAV RDP Protection - Activation</title>
<style>
:root{
  --panel:rgba(19,24,36,.72); --line:rgba(255,255,255,.10); --hair:rgba(255,255,255,.06);
  --text:#f5f7fa; --dim:#93a0b4; --faint:#6b7486;
  --ok:#30d158; --bad:#ff453a; --info:#0a84ff;
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  min-height:100vh;margin:0;display:flex;align-items:center;justify-content:center;padding:24px;
  font:14px/1.55 -apple-system,BlinkMacSystemFont,'SF Pro Text','Segoe UI',system-ui,sans-serif;
  color:var(--text);letter-spacing:-.01em;-webkit-font-smoothing:antialiased;
  background:#05070c;position:relative;overflow:hidden;
}
body::before{content:'';position:fixed;inset:-40%;z-index:0;pointer-events:none;
  background:
    radial-gradient(46% 40% at 24% 20%, rgba(10,132,255,.16), transparent 70%),
    radial-gradient(40% 36% at 78% 16%, rgba(191,90,242,.13), transparent 70%),
    radial-gradient(44% 42% at 60% 82%, rgba(48,209,88,.09), transparent 70%);
  filter:blur(12px);animation:aur 24s ease-in-out infinite alternate}
@keyframes aur{0%{transform:translate3d(-3%,-2%,0)}50%{transform:translate3d(2%,3%,0) rotate(1.4deg)}100%{transform:translate3d(3%,-3%,0) rotate(-1deg)}
}
.card{
  position:relative;z-index:1;width:min(440px,94vw);
  background:var(--panel);border:1px solid var(--hair);border-radius:22px;
  padding:34px 38px 30px;backdrop-filter:blur(28px) saturate(1.5);-webkit-backdrop-filter:blur(28px) saturate(1.5);
  box-shadow:0 24px 70px rgba(0,0,0,.6),0 2px 10px rgba(0,0,0,.4),inset 0 0 0 1px rgba(255,255,255,.02);
  animation:in .5s cubic-bezier(.22,1,.36,1) both}
@keyframes in{from{opacity:0;transform:translateY(16px) scale(.98)}to{opacity:1;transform:none}
}
.tick{width:52px;height:52px;border-radius:15px;margin:0 auto 16px;display:flex;align-items:center;justify-content:center;
  position:relative;
  background:linear-gradient(140deg,rgba(10,132,255,.24),rgba(191,90,242,.18));
  border:1px solid rgba(10,132,255,.35);box-shadow:0 4px 22px rgba(10,132,255,.28)}
.tick svg{width:26px;height:26px;stroke:#dbeeff}

/* Restrained water-drop: a bead slowly forms at the bottom edge of the
   shield, detaches, falls a short distance and fades, and a faint ripple
   answers the impact. One quiet cycle every 3.4 s at ~70% opacity - a
   polished detail, not a toy animation. Skipped under reduced motion. */
.tick::after{
  content:''; position:absolute; left:50%; bottom:-3px;
  width:7px; height:9px; margin-left:-3.5px;
  background:linear-gradient(180deg,#9fd0ff,#5aaaff);
  border-radius:50% 50% 50% 50% / 58% 58% 42% 42%;
  opacity:0; transform:translateY(-2px) scale(0);
  animation:drop 3.4s cubic-bezier(.55,.06,.68,.19) infinite;
}
.tick::before{
  content:''; position:absolute; left:50%; bottom:-8px;
  width:22px; height:9px; margin-left:-11px;
  border-radius:50%; border:1.5px solid rgba(10,132,255,.55);
  opacity:0; transform:scale(.25);
  animation:rip 3.4s ease-out infinite;
}
@keyframes drop{
  0%{opacity:0; transform:translateY(-2px) scale(0)}
  52%{opacity:0; transform:translateY(-2px) scale(0)}
  62%{opacity:.7; transform:translateY(0) scale(.45)}
  76%{opacity:.75; transform:translateY(1px) scale(1)}
  80%{opacity:.75; transform:translateY(2px) scale(.95,1.02)}
  100%{opacity:0; transform:translateY(24px) scale(.6,.75)}
}
@keyframes rip{
  0%{opacity:0; transform:scale(.25)}
  88%{opacity:0; transform:scale(.25)}
  92%{opacity:.5; transform:scale(.6)}
  100%{opacity:0; transform:scale(1.6)}
}
@media (prefers-reduced-motion:reduce){
  .tick::after,.tick::before{animation:none;
  }
}
h1{font-size:21px;font-weight:750;letter-spacing:-.02em;text-align:center}
.sub{color:var(--dim);font-size:13px;text-align:center;margin:6px 0 24px}
label{display:block;font-size:10.5px;color:var(--faint);text-transform:uppercase;letter-spacing:.08em;margin:0 0 7px;font-weight:650}
.asking{
  font-size:34px;font-weight:800;letter-spacing:.22em;color:var(--ok);text-align:center;
  font-family:ui-monospace,Consolas,monospace;margin:2px 0 22px;
  text-shadow:0 0 22px rgba(48,209,88,.45);
  background:rgba(48,209,88,.08);border:1px solid rgba(48,209,88,.25);
  border-radius:14px;padding:12px 10px;animation:in .7s .1s cubic-bezier(.22,1,.36,1) both}
input{
  width:100%;padding:11px 13px;background:rgba(8,11,18,.6);color:var(--text);
  border:1px solid var(--line);border-radius:12px;font-size:15px;font-family:inherit;
  letter-spacing:.06em;transition:border-color .2s,box-shadow .2s;margin-bottom:16px}
input::placeholder{letter-spacing:0;color:var(--faint)}
input:focus{outline:none;border-color:#58a6ff;box-shadow:0 0 0 3.5px rgba(10,132,255,.22)}
button{
  width:100%;padding:12px;background:linear-gradient(180deg,rgba(88,166,255,.98),#0a84ff);
  color:#fff;border:none;border-radius:12px;cursor:pointer;font-size:14px;font-weight:650;
  font-family:inherit;letter-spacing:-.01em;
  box-shadow:0 4px 18px rgba(10,132,255,.38);transition:transform .12s cubic-bezier(.22,1,.36,1),filter .2s}
button:hover{filter:brightness(1.08)}
button:active{transform:scale(.955)}
.mini{width:auto;padding:6px 16px;font-size:11.5px;font-weight:600;margin:-4px 0 16px;
  background:transparent;color:var(--dim);border:1px solid var(--line);box-shadow:none}
.mini:hover{color:var(--ok);border-color:rgba(48,209,88,.35);background:rgba(48,209,88,.06)}
.msg{margin-top:14px;font-size:13px;min-height:18px;text-align:center}
.msg.ok{color:var(--ok)} .msg.bad{color:var(--bad)}
.hint{color:var(--faint);font-size:11.5px;margin-top:14px;text-align:center;line-height:1.6}
</style></head><body>
<div class="card">
  <div class="tick"><svg fill="none" stroke-width="1.8" viewBox="0 0 24 24" stroke="currentColor"><path d="M12 3l7 3v5c0 4.6-3 8.6-7 10-4-1.4-7-5.4-7-10V6l7-3z"/><path d="M9.5 12l1.8 1.8L15 10"/></svg></div>
  <h1>NPAV RDP Protection</h1>
  <div class="sub">Activation required. License valid for 1 year.</div>
  <label>Asking Code</label>
  <div class="asking" id="asking">------</div>
  <button class="mini" onclick="shuffle()">&#8635; New asking code</button>
  <label>Enter 6-digit Dynamic Activation Key / Master Password</label>
  <input id="key" maxlength="24" autocomplete="off" placeholder="Activation key">
  <button onclick="verify()">Activate</button>
  <div class="msg" id="msg"></div>
  <div class="hint">Provide the asking code to your administrator to receive the activation key.<br>Master password may also be used.</div>
</div>
<script>
const TOKEN='{{token}}';
async function api(p, body){
  const r = await fetch(p + (p.includes('?')?'&':'?') + 't=' + TOKEN,
    {method: body?'POST':'GET', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: body||null});
  if(!r.ok){
    let d=''; try{ d=(await r.text()).trim(); }catch(e){
    }
    throw new Error(d || ('HTTP '+r.status));
  }
  return r.text();
}
async function loadAsking(){
  try {
    const r = await api('/api/activate/asking');
    const j = JSON.parse(r);
    document.getElementById('asking').textContent = j.asking;
  } catch(e){ document.getElementById('asking').textContent = 'ERROR'; }
}
async function verify(){
  const key = document.getElementById('key').value.trim();
  const msg = document.getElementById('msg');
  msg.className='msg'; msg.textContent='Verifying...';
  try {
    const r = await api('/api/activate/verify', 'key=' + encodeURIComponent(key));
    if(r === 'activated'){
      msg.className='msg ok'; msg.textContent='Activation successful. Opening dashboard...';
      // Swap to the dashboard in place: fetch the boot shell and replace the
      // document - no reload, the page keeps its scroll position and size.
      fetch('/').then(function(x){
        return x.text();
      }).then(function(html){
        setTimeout(function(){
          document.open(); document.write(html); document.close();
        }, 500);
      }).catch(function(){
        location.reload();
      });
    }
    else { msg.className='msg bad'; msg.textContent = (r === 'invalid') ? 'Invalid key. Try again.' : r; }
  } catch(e){ msg.className='msg bad'; msg.textContent = (e && e.message) || 'Request failed.'; }
}
loadAsking();
async function shuffle(){
  const el = document.getElementById('asking'); const old = el.textContent;
  el.textContent = '······';
  try {
    const r = await api('/api/activate/asking', 'x=1');
    el.textContent = JSON.parse(r).asking;
  } catch(e){ el.textContent = old; }
}
document.getElementById('key').addEventListener('keydown', e=>{ if(e.key==='Enter') verify(); });
</script></body></html>
""";
    }
}
