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
    { file: "Duelito.nes",    name: "Duelito" },
    { file: "apocalypse.nes", name: "Apocalypse" },
    { file: "Deadline.nes",   name: "Deadline (8bitpeoples)" },
    { file: "Sayoonara.nes",  name: "Sayoonara!" },
    { file: "minipack.nes",   name: "MiniPack demo" }
  ];

  var nes = null, romName = "", paused = false, sound = true, raf = null;
  var audioCtx = null;

  var el = {
    screen: null, ctx: null, msg: null, status: null, games: null,
    btnPause: null, btnReset: null, btnVol: null, btnFull: null
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

  function fetchRom(url, name) {
    el.status.textContent = "Загружаю " + name + "…";
    fetch(url).then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.arrayBuffer();
    }).then(function (ab) {
      loadRom(ab, name);
    }).catch(function (e) {
      setMsg("Ошибка загрузки ROM: " + e.message);
    });
  }

  function gameList() {
    el.games.innerHTML = "";
    ROMS.forEach(function (g, i) {
      var b = document.createElement("button");
      b.className = "game" + (i === 0 ? " on" : "");
      var b2 = document.createElement("b"); b2.textContent = g.name;
      var s = document.createElement("small"); s.textContent = g.file;
      b.appendChild(b2); b.appendChild(s);
      b.addEventListener("click", function () {
        var all = el.games.querySelectorAll("button.game");
        for (var k = 0; k < all.length; k++) all[k].classList.remove("on");
        b.classList.add("on");
        fetchRom("roms/" + encodeURIComponent(g.file), g.name);
      });
      el.games.appendChild(b);
    });
    el.status.textContent = ROMS.length + " игр";
  }

  function setKey(name, down) {
    if (!nes) return;
    if (down) nes.buttonDown(name); else nes.buttonUp(name);
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

    newNes();
    controlsOn(false);
    gameList();
    fetchRom("roms/" + encodeURIComponent(ROMS[0].file), ROMS[0].name);

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
    el.btnFull.addEventListener("click", function () {
      var s = el.screen;
      if (s.requestFullscreen) s.requestFullscreen();
      else if (s.webkitRequestFullscreen) s.webkitRequestFullscreen();
    });
    el.screen.addEventListener("click", function () {
      if (nes) setPaused(!paused);
    });

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