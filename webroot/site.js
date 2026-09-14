(function () {
  "use strict";

  var KEYMAP = {
    "B": ["b", 83],
    "A": ["a", 68],
    "SELECT": ["ShiftLeft", 76],
    "START": ["Enter", 81],
    "UP": ["ArrowUp", 70],
    "DOWN": ["ArrowDown", 86],
    "LEFT": ["ArrowLeft", 73],
    "RIGHT": ["ArrowRight", 74]
  };

  var KEYCODE = {
    "ArrowUp": "UP", "ArrowDown": "DOWN", "ArrowLeft": "LEFT", "ArrowRight": "RIGHT",
    "ShiftLeft": "SELECT", "ShiftRight": "SELECT", "Enter": "START",
    "KeyS": "B", "KeyA": "A", "KeyD": "B", "KeyF": "A",
    "KeyW": "UP", "KeyX": "DOWN",
    "Space": "PAUSE", "KeyQ": "RESET"
  };

  var ROMS = [
    { file: "smb.nes",         name: "Super Mario Bros.",         sub: "Nintendo · 1985" },
    { file: "battlecity.nes",  name: "Battle City",               sub: "Namco · 1985" },
    
    { file: "chipndale.nes",   name: "Chip 'n Dale Rescue Rangers", sub: "Capcom · 1990" },
    { file: "battletadsdd.nes", name: "Battletoads & Double Dragon", sub: "Rare · 1993" }
  ];

  var nes = null, romName = "", paused = false, sound = true, raf = null;
  var audioCtx = null;

  var el = {
    screen: null, ctx: null, msg: null, status: null, games: null,
    btnPause: null, btnReset: null, btnVol: null, btnFull: null, btnPad: null, pad: null
  };

  function $(id) { return document.getElementById(id); }

  function newNes() {
    nes = new jsnes.NES({
      onFrame: function (buf) {
        var ctx = el.ctx;
        var img = ctx.createImageData(256, 240);
        var d = img.data, i = 0;
        for (var y = 0; y < 240; y++) {
          for (var x = 0; x < 256; x++) {
            var p = buf[i++];
            var o = (y * 256 + x) * 4;
            d[o] = p & 255;
            d[o + 1] = (p >> 8) & 255;
            d[o + 2] = (p >> 16) & 255;
            d[o + 3] = 255;
          }
        }
        ctx.putImageData(img, 0, 0);
      },
      onAudioSample: function (l, r) {
        if (!sound) return;
        try {
          if (!audioCtx) {
            audioCtx = new (window.AudioContext || window.webkitAudioContext)();
          }
          if (audioCtx.state === "suspended") audioCtx.resume();
          var buf = audioCtx.createBuffer(2, 1, 44100);
          buf.getChannelData(0)[0] = l;
          buf.getChannelData(1)[0] = r;
          var src = audioCtx.createBufferSource();
          src.buffer = buf;
          src.connect(audioCtx.destination);
          src.start();
        } catch (e) {}
      }
    });
  }

  function frame() {
    if (!nes) return;
    nes.frame();
    if (raf) raf = requestAnimationFrame(frame);
  }

  function setPaused(v) {
    paused = v;
    el.btnPause.textContent = paused ? "▶ Продолжить" : "⏸ Пауза";
  }

  function loadRom(u8, name) {
    try {
      if (!nes) newNes();
      var arr = (u8 instanceof Uint8Array) ? u8 : new Uint8Array(u8);
      var str = "", chunk = 32768;
      for (var i = 0; i < arr.length; i += chunk) {
        str += String.fromCharCode.apply(null, arr.subarray(i, i + chunk));
      }
      nes.loadROM(str);
      romName = name || "игра";
      controlsOn(true);
      setPaused(false);
      el.status.textContent = "Игра: " + romName;
      setMsg("");
      if (raf) cancelAnimationFrame(raf);
      raf = requestAnimationFrame(frame);
      setTimeout(function () {
        if (audioCtx && audioCtx.state === "suspended") audioCtx.resume();
      }, 200);
    } catch (e) {
      setMsg("Не удалось загрузить ROM: " + e.message);
    }
  }

  function controlsOn(on) {
    el.btnReset.disabled = !on;
    el.btnPause.disabled = !on;
  }

  function setMsg(t) { el.msg.textContent = t; }

  function fetchRom(url, name, file) {
    el.status.textContent = "Загружаю " + name + "…";
    fetch(url).then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.arrayBuffer();
    }).then(function (ab) {
      loadRom(ab, name);
    }).catch(function (e) {
      setMsg("ROM «" + name + "» не найден (" + file + "). Положите файл в roms/.");
    });
  }

  function gameList() {
    el.games.innerHTML = "";
    ROMS.forEach(function (g, i) {
      var b = document.createElement("button");
      b.className = "game" + (i === 0 ? " on" : "");
      var b2 = document.createElement("b"); b2.textContent = g.name;
      var s = document.createElement("small"); s.textContent = g.sub;
      b.appendChild(b2); b.appendChild(s);
      b.addEventListener("click", function () {
        var all = el.games.querySelectorAll("button.game");
        for (var k = 0; k < all.length; k++) all[k].classList.remove("on");
        b.classList.add("on");
        fetchRom("roms/" + encodeURIComponent(g.file), g.name, g.file);
      });
      el.games.appendChild(b);
    });
    el.status.textContent = ROMS.length + " игр";
  }

  function setKey(name, down) {
    if (!nes) return;
    if (down) nes.buttonDown(name); else nes.buttonUp(name);
  }

  function bindTouchBtn(b) {
    var name = b.getAttribute("data-btn");
    function on(e) {
      e.preventDefault();
      b.classList.add("pressed");
      setKey(name, true);
    }
    function off(e) {
      if (e) e.preventDefault();
      b.classList.remove("pressed");
      setKey(name, false);
    }
    b.addEventListener("touchstart", on, { passive: false });
    b.addEventListener("touchend", off, { passive: false });
    b.addEventListener("touchcancel", off, { passive: false });
    b.addEventListener("mousedown", function (e) { e.preventDefault(); on(e); });
    b.addEventListener("mouseup", off);
    b.addEventListener("mouseleave", off);
  }

  function isTouch() {
    return ("ontouchstart" in window) || (navigator.maxTouchPoints > 0);
  }

  function padVisible() { return !el.pad.hidden; }

  function setPad(on) {
    el.pad.hidden = !on;
    if (on) document.body.classList.add("has-pad");
    else document.body.classList.remove("has-pad");
    el.btnPad.textContent = on ? "🎮 ✓" : "🎮";
  }

  function fitCanvas() {
    var stage = document.getElementById("stage");
    if (!stage) return;
    var W = stage.clientWidth, H = stage.clientHeight;
    if (W && H) {
      var s = Math.min(W / 256, H / 240);
      el.screen.style.width = Math.floor(256 * s) + "px";
      el.screen.style.height = Math.floor(240 * s) + "px";
    }
  }

  var fsSim = false;

  function fsClass(on) {
    document.body.classList.toggle("fs-sim", on);
    document.body.classList.toggle("fs", on);
    el.btnExitFull.hidden = !on;
    if (on) document.body.classList.add("has-pad");
  }

  function onFsChange() {
    var real = !!(document.fullscreenElement || document.webkitFullscreenElement);
    fsClass(real);
    fsSim = false;
    fitCanvas();
  }

  function tryLock() {
    try {
      if (!(document.fullscreenElement || document.webkitFullscreenElement)) return;
      var o = screen.orientation;
      if (o && o.lock && o.lock.call) o.lock("landscape").catch(function () {});
    } catch (e) {}
  }

  function toggleFullscreen() {
    if (document.fullscreenElement || document.webkitFullscreenElement) {
      exitFullscreen();
      return;
    }
    if (fsSim) { exitFullscreen(); return; }
    var stage = document.getElementById("stage");
    var req = stage.requestFullscreen || stage.webkitRequestFullscreen;
    if (req && !isIosSafari()) {
      try {
        req.call(stage);
        setTimeout(function () {
          if (!(document.fullscreenElement || document.webkitFullscreenElement)) simFs();
          else tryLock();
        }, 300);
      } catch (e) { simFs(); }
      return;
    }
    simFs();
  }

  function exitFullscreen() {
    if (document.fullscreenElement || document.webkitFullscreenElement) {
      var exf = document.exitFullscreen || document.webkitExitFullscreen;
      if (exf) exf.call(document);
      else { fsSim = false; fsClass(false); }
      return;
    }
    fsSim = false;
    fsClass(false);
  }

  function isIosSafari() {
    var ua = navigator.userAgent;
    return /iPhone|iPad|iPod/i.test(ua) && /Safari/i.test(ua) && !/CriOS|FxiOS|OPT|Edge/i.test(ua);
  }

  function simFs() {
    if (document.fullscreenElement || document.webkitFullscreenElement) return;
    fsSim = true;
    fsClass(true);
    fitCanvas();
  }

  function setup() {
    el.screen = $("screen");
    el.ctx = el.screen.getContext("2d");
    el.msg = $("msg");
    el.status = $("status");
    el.games = $("games");
    el.btnPause = $("btnPause");
    el.btnReset = $("btnReset");
    el.btnVol = $("btnVol");
    el.btnFull = $("btnFull");
    el.btnPad = $("btnPad");
    el.pad = $("pad");
    el.btnExitFull = $("btnExitFull");

    newNes();
    controlsOn(false);
    gameList();

    if (isTouch()) {
      setPad(true);
      var keys = el.pad.querySelectorAll(".k");
      for (var i = 0; i < keys.length; i++) bindTouchBtn(keys[i]);
    } else {
      setPad(false);
    }

    fetchRom("roms/" + encodeURIComponent(ROMS[0].file), ROMS[0].name, ROMS[0].file);

    el.btnReset.addEventListener("click", function () {
      if (nes) { nes.reset(); setMsg("Сброс"); }
    });
    el.btnPause.addEventListener("click", function () {
      if (nes) setPaused(!paused);
    });
    el.btnVol.addEventListener("click", function () {
      sound = !sound;
      el.btnVol.textContent = sound ? "🔊 Звук" : "🔇 Тихо";
    });
    el.btnFull.addEventListener("click", toggleFullscreen);
    el.btnExitFull.addEventListener("click", exitFullscreen);
    el.btnPad.addEventListener("click", function () {
      setPad(!padVisible());
    });
    el.screen.addEventListener("click", function () {
      if (nes) setPaused(!paused);
    });

    document.addEventListener("fullscreenchange", onFsChange);
    document.addEventListener("webkitfullscreenchange", onFsChange);
    window.addEventListener("resize", fitCanvas);

    var btnUp = document.createElement("button");
    btnUp.textContent = "⬆ Загрузить .nes";
    btnUp.style.cssText = "flex:1 1 100%";
    btnUp.addEventListener("click", function () {
      var inp = document.createElement("input");
      inp.type = "file"; inp.accept = ".nes,application/octet-stream";
      var rd = new FileReader();
      inp.addEventListener("change", function () {
        var f = inp.files[0];
        if (!f) return;
        rd.onload = function () { loadRom(rd.result, f.name); };
        rd.readAsArrayBuffer(f);
      });
      inp.click();
    });
    el.games.appendChild(btnUp);

    window.addEventListener("keydown", function (e) {
      var k = KEYCODE[e.code];
      if (!k) return;
      e.preventDefault();
      if (k === "PAUSE") { if (nes) setPaused(!paused); return; }
      if (k === "RESET") { if (nes) { nes.reset(); setMsg("Сброс"); } return; }
      setKey(k, true);
    });
    window.addEventListener("keyup", function (e) {
      var k = KEYCODE[e.code];
      if (!k) return;
      e.preventDefault();
      if (k === "PAUSE" || k === "RESET") return;
      setKey(k, false);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", setup);
  } else {
    setup();
  }
})();