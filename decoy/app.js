'use strict';
/* ---------- реестр игр ---------- */
const GAMES = [
  { id:'roborun', title:'RoboRun',  file:'roborun.nes', region:'Dendy', genre:'Платформер · раннер',
    tags:['P1','GPL-3.0'], desc:'Робот-бегун уворачивается от препятствий. Управление: крестовина + A (прыжок).',
    icon:'robot' },
  { id:'falling', title:'Falling',  file:'falling.nes', region:'Auto', genre:'Головоломка',
    tags:['P1','MIT'], desc:'Классика падающих блоков на чистом NROM: собирай линии, не дай экрану переполниться.',
    icon:'blocks' },
  { id:'yourown', title:'Своя ROM', file:null, region:'Auto', genre:'Загрузить .nes',
    tags:['iNES'], desc:'Перетащи свой дамп iNES (.nes) — запустится на этом же эмуляторе. Файл никуда не отправляется.',
    icon:'folder' },
];

/* pixel-art иконки (заливаем сетку из матрицы) */
const PX = {
  robot:  ['#0000000','01111110','14444441','15444451','14444441','01444410','00144100','01144110','01011010'],
  blocks: ['#0000000','02222220','23333332','23323232','23333332','02222220','0066660','06777760','06777760'],
  folder: ['#0000000','01111100','01777110','01777710','07777770','07777770','07777770','07777770','00000000'],
  play:   ['#0000000','0001000','0011100','0111110','0011100','0001000','0000000','0000000','0000000'],
};
const PAL = {0:'#00000000',1:'#ef4444',2:'#1f2b45',3:'#38bdf8',4:'#fbbf24',5:'#e6edf8',6:'#0b0f1a',7:'#94a3b8'};
function pixelSvg(name){
  const m = PX[name]; if(!m) return '';
  let r = '';
  for(let y=0;y<m.length;y++) for(let x=0;x<9;x++){
    const c = PAL[m[y][x]]; if(!c||c==='#00000000') continue;
    r += `<rect x="${x}" y="${y}" width="1.02" height="1.02" fill="${c}"/>`;
  }
  return `<svg viewBox="0 0 9 9" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">${r}</svg>`;
}

/* ---------- DOM ---------- */
const $ = id => document.getElementById(id);
const canvas = $('screen'), ctx = canvas.getContext('2d', {alpha:false});

/* карточки */
$('heroGame').textContent = GAMES[0].title;
const grid = $('gameGrid');
for(const g of GAMES){
  const el = document.createElement('div'); el.className='card';
  el.innerHTML =
    `<div class="art">${pixelSvg(g.icon)}</div>`+
    `<h3>${g.title}</h3><p class="meta"><b>${g.genre}</b> · ${g.desc}</p>`+
    `<div>${g.tags.map(t=>`<span class="badge ${t==='P1'?'g':t==='MIT'?'b':''}">${t}</span>`).join(' ')}</div>`+
    `<button class="btn primary play">${g.file?'▶ Играть':'📁 Открыть .nes'}</button>`;
  el.querySelector('.play').addEventListener('click', ()=> g.file ? launchRom(g) : $('romInput').click());
  grid.appendChild(el);
}
$('heroPlay').addEventListener('click', ()=> launchRom(GAMES[0]));

function toast(msg){
  const t = $('toast'); t.textContent = msg; t.classList.add('show');
  clearTimeout(t._h); t._h = setTimeout(()=>t.classList.remove('show'), 2200);
}

/* ---------- эмулятор: FCEUmm (libretro, WASM) ---------- */
let eng = null, engModule = null, running = false, paused = false, raf = 0;
let curRom = null, frameCount = 0, lastT = 0, acc = 0;
let audioCtx = null, gainNode = null, procNode = null, muted = false;

function loadSram(name){
  try{ const v = localStorage.getItem('srm:'+name); if(!v) return null;
    const b = atob(v), a = new Uint8Array(b.length);
    for(let i=0;i<b.length;i++) a[i]=b.charCodeAt(i); return a;
  }catch(e){ return null; }
}
function saveSram(name, bytes){
  try{ if(!bytes || !bytes.length) return;
    let s=''; const CH=8192;
    for(let i=0;i<bytes.length;i+=CH) s+=String.fromCharCode.apply(null, bytes.subarray(i,i+CH));
    localStorage.setItem('srm:'+name, btoa(s));
  }catch(e){}
}
async function bootRom(file, bytes, region){
  if(!engModule) engModule = await import('./nes-engine.js');
  destroyEngine();
  eng = await engModule.createNesEngine({ romBytes: bytes, romName: file, region: region||'Auto', sram: loadSram(file) });
  curRom = file; frameCount = 0;
  eng.setRgbaTarget(canvas);
}
function destroyEngine(){
  running = false; if(raf) cancelAnimationFrame(raf); raf = 0;
  if(eng){ try{ const s = eng.saveRam(); if(s && curRom) saveSram(curRom, s); }catch(e){} try{ eng.unload(); }catch(e){} eng = null; }
}
function ensureAudio(){
  if(audioCtx || !window.AudioContext) return;
  try{
    audioCtx = new AudioContext({ sampleRate: eng ? eng.avInfo.sampleRate : 48000 });
    gainNode = audioCtx.createGain(); gainNode.gain.value = muted?0:0.4;
    procNode = audioCtx.createScriptProcessor(2048, 2, 2);
    procNode.onaudioprocess = e => {
      const L = e.outputBuffer.getChannelData(0), R = e.outputBuffer.getChannelData(1);
      if(!eng || paused){ L.fill(0); R.fill(0); return; }
      const tmp = new Float32Array(L.length*2);
      eng.audio.read(tmp);
      for(let i=0;i<L.length;i++){ L[i]=tmp[2*i]; R[i]=tmp[2*i+1]; }
    };
    procNode.connect(gainNode); gainNode.connect(audioCtx.destination);
  }catch(e){ audioCtx = null; }
}
function blackScreen(){ ctx.fillStyle = '#060a14'; ctx.fillRect(0,0,canvas.width,canvas.height); }

function loop(t){
  if(!running){ raf = 0; return; }
  raf = requestAnimationFrame(loop);
  if(paused || !eng){ lastT = 0; return; }
  const fps = eng.avInfo.fps || 60, dur = 1000/fps;
  if(!lastT) lastT = t;
  acc += (t - lastT); lastT = t;
  if(acc > dur*4) acc = dur*2;
  let steps = 0;
  while(acc >= dur && steps < 3){ acc -= dur; steps++; try{ eng.runFrame(); }catch(e){ break; } }
  if(steps){
    eng.blit();
    frameCount += steps;
    if(frameCount % Math.round(fps*10) === 0 && curRom){ try{ saveSram(curRom, eng.saveRam()); }catch(e){} }
  }
}
let osBtnFn = null;
function showOverlay(title, text, btnText, btnFn){
  const o=$('oscrim'); o.classList.remove('hidden');
  $('osTitle').textContent = title; $('osText').textContent = text;
  $('osBtn').textContent = btnText; osBtnFn = btnFn;
}
$('osBtn').addEventListener('click', ()=>{ if(osBtnFn) osBtnFn(); });
function hideOverlay(){ $('oscrim').classList.add('hidden'); }

function lockPage(on){ document.body.classList.toggle('locked', on); }

function startRomInGameView(){
  ensureAudio(); if(audioCtx && audioCtx.state === 'suspended') audioCtx.resume();
  hideOverlay(); $('game').classList.remove('hidden');
  lockPage(true);
  running = true; paused = false; lastT = 0; acc = 0; setPauseIcon();
  if(raf) cancelAnimationFrame(raf); raf = requestAnimationFrame(loop);
  vibrate(30);
}
function launchRom(g){
  $('gTitle').textContent = g.title;
  blackScreen();
  $('game').classList.remove('hidden');
  lockPage(true);
  running = false; paused = false; setPauseIcon();
  if(raf) cancelAnimationFrame(raf);
  showOverlay(g.title, 'Нажми «Начать», чтобы включить консоль. Звук включится после первого нажатия.', '▶ Начать', ()=>{
    const btn = $('osBtn'); btn.disabled = true; $('osText').textContent = 'Запуск FCEUmm…';
    fetch(g.file).then(r=>{ if(!r.ok) throw new Error('rom'); return r.arrayBuffer(); })
      .then(b=> bootRom(g.file, new Uint8Array(b), g.region))
      .then(()=> startRomInGameView())
      .catch(()=> showOverlay('Не удалось запустить', 'Файл '+g.file+' не похож на корректный NES-дамп.', '🏠 На главную', quitGame))
      .finally(()=>{ btn.disabled = false; });
  });
}

/* свой ROM — загружается локально, никуда не отправляется */
$('romInput').addEventListener('change', ev=>{
  const f = ev.target.files[0]; ev.target.value = '';
  if(!f) return;
  f.arrayBuffer().then(b=>{
    const v = new Uint8Array(b);
    if(v.length < 16 || v[0]!==0x4e||v[1]!==0x45||v[2]!==0x53||v[3]!==0x1a){
      toast('Это не iNES-ром (.nes)'); return;
    }
    const name = 'user_'+f.name.replace(/[^a-zA-Z0-9._-]/g,'_').slice(-60);
    $('gTitle').textContent = f.name.replace(/\.nes$/i,'').slice(0,24);
    blackScreen();
    $('game').classList.remove('hidden'); lockPage(true);
    bootRom(name, v, 'Auto').then(()=> startRomInGameView())
      .catch(()=>{ toast('ROM не запустилась'); quitGame(); });
  });
});
$('openRom').addEventListener('click', ()=>$('romInput').click());

/* ---------- вывод игры ---------- */
function quitGame(){
  destroyEngine();
  document.querySelectorAll('.hit').forEach(e=>e.classList.remove('hit'));
  $('game').classList.add('hidden');
  lockPage(false);
  if(document.fullscreenElement) document.exitFullscreen().catch(()=>{});
  blackScreen();
}
$('btnQuit').addEventListener('click', quitGame);

function setPauseIcon(){ $('btnPause').textContent = paused ? '▶' : '⏸'; }
function togglePause(){ if(!running) return; paused = !paused; setPauseIcon();
  if(audioCtx){ paused ? audioCtx.suspend() : audioCtx.resume(); } }
$('btnPause').addEventListener('click', togglePause);

function toggleSound(){
  muted = !muted;
  if(gainNode) gainNode.gain.value = muted?0:0.35;
  const b=$('btnSound'); b.textContent = muted?'🔇':'🔊'; b.classList.toggle('off',muted);
}
$('btnSound').addEventListener('click', toggleSound);

function toggleCrt(){
  const g=$('game'); g.classList.toggle('crt');
  $('btnCrt').classList.toggle('off', !g.classList.contains('crt'));
}
$('btnCrt').addEventListener('click', toggleCrt);

function toggleFs(){
  const el = $('game');
  if(!document.fullscreenElement){ (el.requestFullscreen||el.webkitRequestFullscreen).call(el).catch(()=>{}); }
  else document.exitFullscreen().catch(()=>{});
}
$('btnFs').addEventListener('click', toggleFs);

function vibrate(ms){ if(navigator.vibrate) try{navigator.vibrate(ms);}catch(e){} }

/* ---------- ввод: кнопки ---------- */
function press(name, down, el){
  if(eng) eng.button(name, down);
  if(el) el.classList.toggle('hit', down);
}
/* pointer-события с мультитачем */
document.querySelectorAll('[data-btn]').forEach(el=>{
  const name = el.dataset.btn;
  const held = new Set();
  const on = e =>{
    e.preventDefault();
    held.add(e.pointerId !== undefined ? e.pointerId : 'm');
    press(name, true, el);
    if(el.setPointerCapture && e.pointerId !== undefined) try{ el.setPointerCapture(e.pointerId); }catch(err){}
  };
  const off = e =>{
    held.delete(e.pointerId !== undefined ? e.pointerId : 'm');
    if(!held.size) press(name, false, el);
  };
  if(window.PointerEvent){
    el.addEventListener('pointerdown', on);
    el.addEventListener('pointerup', off);
    el.addEventListener('pointercancel', off);
    el.addEventListener('lostpointercapture', off);
  }else{
    el.addEventListener('touchstart', e=>{e.preventDefault(); held.add('t'); press(name,true,el);}, {passive:false});
    el.addEventListener('touchend', off); el.addEventListener('touchcancel', off);
    el.addEventListener('mousedown', on); el.addEventListener('mouseup', off);
  }
  el.addEventListener('contextmenu', e=>e.preventDefault());
});

/* ---------- ввод: клавиатура ---------- */
const KEYS = {
  ArrowUp:'UP', KeyW:'UP', ArrowDown:'DOWN', KeyS:'DOWN', ArrowLeft:'LEFT', KeyA:'LEFT', ArrowRight:'RIGHT', KeyD:'RIGHT',
  KeyZ:'A', KeyJ:'A', KeyX:'B', KeyK:'B', Enter:'START', ShiftLeft:'SELECT', ShiftRight:'SELECT', Space:'A',
};
const keyHeld = {};
window.addEventListener('keydown', e=>{
  if(e.repeat) return;
  const code = e.code;
  if(code==='KeyP'){ togglePause(); return; }
  if(code==='KeyM'){ toggleSound(); return; }
  if(code==='KeyC'){ toggleCrt(); return; }
  if(code==='KeyF'){ toggleFs(); return; }
  if(KEYS[code] && !$('game').classList.contains('hidden')){
    press(KEYS[code], true); keyHeld[code] = KEYS[code]; e.preventDefault();
  }
});
window.addEventListener('keyup', e=>{
  if(keyHeld[e.code]){ press(keyHeld[e.code], false); delete keyHeld[e.code]; }
});
window.addEventListener('blur', ()=>{ for(const k in keyHeld){ press(keyHeld[k], false); delete keyHeld[k]; } });

/* ---------- ввод: геймпад ---------- */
const GP = {0:'A', 2:'B', 8:'SELECT', 9:'START', 12:'UP', 13:'DOWN', 14:'LEFT', 15:'RIGHT'};
const gpState = {};
function pollPad(){
  requestAnimationFrame(pollPad);
  if($('game').classList.contains('hidden')) return;
  const pads = navigator.getGamepads ? navigator.getGamepads() : [];
  const g = Array.prototype.find.call(pads, p=>p);
  if(!g) return;
  const set = (name, down) => { if(!!gpState[name] !== down){ press(name, down); gpState[name] = down; } };
  for(const idx in GP){
    const b = g.buttons[+idx];
    if(b) set(GP[idx], !!b.pressed);
  }
  const ax = g.axes || [];
  set('UP',    (ax[1]||0) < -.55);
  set('DOWN',  (ax[1]||0) >  .55);
  set('LEFT',  (ax[0]||0) < -.55);
  set('RIGHT', (ax[0]||0) >  .55);
}
window.addEventListener('gamepadconnected', e=>toast('Геймпад подключён: '+String(e.gamepad.id).slice(0,40)));
pollPad();

/* подсказка при первом тапе по геймпаду без ROM */
blackScreen();
