// Минимальный браузерный libretro-хост для FCEUmm (NES).
// API: createNesEngine({romBytes, region, audio}) -> {canvas-ready frame loop}
const E = {
  GET_CAN_DUPE: 3, SET_MESSAGE: 6, GET_SYSTEM_DIRECTORY: 9, SET_PIXEL_FORMAT: 10,
  SET_INPUT_DESCRIPTORS: 11, GET_VARIABLE: 15, SET_VARIABLES: 16, GET_VARIABLE_UPDATE: 17,
  SET_SUPPORT_NO_GAME: 18, GET_LOG_INTERFACE: 27, GET_PERF_INTERFACE: 28,
  GET_SAVE_DIRECTORY: 31, SET_GEOMETRY: 37, GET_USERNAME: 38, GET_LANGUAGE: 39,
  GET_CORE_OPTIONS_VERSION: 52, SET_CORE_OPTIONS: 53, SET_CORE_OPTIONS_INTL: 54,
  SET_CORE_OPTIONS_V2: 67, SET_CORE_OPTIONS_V2_INTL: 68, GET_AUDIO_VIDEO_ENABLE: 47,
  GET_INPUT_BITMASKS: 51, GET_CONTENT_DIRECTORY: 30,
  SET_PERFORMANCE_LEVEL: 8, SET_KEYBOARD_CALLBACK: 12, SET_CONTROLLER_INFO: 35,
  SET_SUBSYSTEM_INFO: 34, SET_MEMORY_MAPS: 36, SET_SUPPORT_ACHIEVEMENTS: 42,
  SET_VARIABLE: 70,
};
const PIX = { XRGB8888: 1, RGB565: 2, _0RGB1555: 0 };
export const BUTTONS = { B:0, Y:1, SELECT:2, START:3, UP:4, DOWN:5, LEFT:6, RIGHT:7, A:8, X:9, L:10, R:11 };

function cstring(s){ const e=new TextEncoder().encode(s); const a=new Uint8Array(e.length+1); a.set(e); return a; }

export async function createNesEngine({ romBytes, romName="game.nes", region="Auto", sram=null, onFrame, onFatal }) {
  const base = new URL('cores/fceumm/', location.href).href;
  const factory = (await import(base + 'fceumm.js')).default;
  const wasmBinary = await (await fetch(base + 'fceumm.wasm')).arrayBuffer();
  const mod = await factory({ wasmBinary, noInitialRun: true, canvas: null });

  const st = {
    pixelFormat: PIX._0RGB1555,
    coreVariables: new Map(),
    variablesUpdated: false,
    inputPorts: [new Uint16Array(1), new Uint16Array(1)],
    keysDown: new Set(),
    keep: [],
  };
  st.coreVariables.set("fceumm_region", { description:"Region", options:["Auto","NTSC","PAL","Dendy"], value: region });
  if (region !== "Auto") st.variablesUpdated = true;

  const u8 = () => mod.HEAPU8, u32 = () => mod.HEAPU32, i32v = () => mod.HEAP32;
  const poke32 = (p, v) => { u32()[p >> 2] = v; };
  const peek32 = (p) => u32()[p >> 2];
  const peek8 = (p) => u8()[p];
  function readStr(p) {
    if (!p) return null;
    const b = u8(); let e = p; while (b[e] !== 0) e++;
    return new TextDecoder().decode(b.subarray(p, e));
  }
  function allocString(str) {
    const bytes = cstring(str); const ptr = mod._malloc(bytes.length);
    u8().set(bytes, ptr); st.keep.push(ptr); return ptr;
  }

  // ---- framebuffer / audio targets (set after av info known) ----
  let rgbaBuf = null, rgba32 = null, imgData = null, ctx2d = null;
  let fbW = 256, fbH = 240, pitch = 0;
  let audioRing = new Float32Array(1 << 16), wr = 0, rd = 0; // power-of-two ring, stereo frames
  const ARMASK = audioRing.length / 2 - 1;
  let avInfo = { fps: 60, sampleRate: 44100 };

  function audioWrite(samplesF32) { // interleaved stereo floats
    const n = samplesF32.length / 2;
    const cap = ARMASK + 1;
    if (wr - rd + n > cap) rd = wr - cap + n; // drop oldest to bound latency
    for (let i = 0; i < n; i++) {
      const w = (wr & ARMASK) * 2;
      audioRing[w] = samplesF32[i*2]; audioRing[w+1] = samplesF32[i*2+1];
      wr++;
    }
  }
  function audioAvailable(){ return wr - rd; }
  function audioRead(outF32) { // outF32 interleaved stereo; fills with silence on underrun
    const n = outF32.length / 2; let avail = wr - rd;
    for (let i = 0; i < n; i++) {
      if (avail > 0) { const w = (rd & ARMASK) * 2; outF32[i*2] = audioRing[w]; outF32[i*2+1] = audioRing[w+1]; rd++; avail--; }
      else { outF32[i*2] = 0; outF32[i*2+1] = 0; }
    }
  }

  // ---- callbacks ----
  const envCb = mod.addFunction((cmd, dataPtr) => {
    const r = handleEnv(cmd, dataPtr) ? 1 : 0;
    (st.envTrace ||= []).push(cmd + ":" + r);
    return r;
  }, "iii");
  mod._retro_set_environment(envCb);

  const videoCb = mod.addFunction((dataPtr, w, h, p) => {
    if ((dataPtr >>> 0) === 0 || (dataPtr >>> 0) === 0xFFFFFFFF) return; // null / dup
    if (w > 0 && h > 0) { fbW = w; fbH = h; }
    pitch = Math.abs(p);
    const need = fbW * fbH * 4;
    if (!rgbaBuf || rgbaBuf.length !== need) {
      rgbaBuf = new Uint8Array(need); rgba32 = new Uint32Array(rgbaBuf.buffer);
    }
    decode(dataPtr, u8(), w, h, pitch, rgba32, st.pixelFormat);
    if (imgData && (imgData.width !== fbW || imgData.height !== fbH)) imgData = null;
    if (onFrame) onFrame(rgba32, fbW, fbH);
  }, "viiii");
  mod._retro_set_video_refresh(videoCb);

  const audioBatchCb = mod.addFunction((dataPtr, frames) => {
    if (!dataPtr || !frames) return frames;
    const src = new Int16Array(mod.HEAPU8.buffer, dataPtr, frames * 2);
    const f = new Float32Array(frames * 2);
    for (let i = 0; i < f.length; i++) f[i] = src[i] / 32768;
    audioWrite(f);
    return frames;
  }, "iii");
  mod._retro_set_audio_sample_batch(audioBatchCb);

  const audioOneCb = mod.addFunction((l, r) => {
    audioWrite(new Float32Array([l / 32768, r / 32768]));
  }, "vii");
  mod._retro_set_audio_sample(audioOneCb);

  const pollCb = mod.addFunction(() => {}, "v");
  mod._retro_set_input_poll(pollCb);

  const stateCb = mod.addFunction((port, device, index, id) => {
    if (device === 3) return st.keysDown.has(id) ? 1 : 0;
    const word = st.inputPorts[port] ? st.inputPorts[port][0] : 0;
    if (id === 256) return word;
    return (word & (1 << id)) ? 1 : 0;
  }, "iiiii");
  mod._retro_set_input_state(stateCb);

  function handleEnv(rawCmd, dataPtr) {
    const cmd = rawCmd & ~0x10000;
    switch (cmd) {
      case E.GET_CAN_DUPE: u8()[dataPtr] = 1; return true;
      case E.SET_MESSAGE: return true;
      case E.GET_LOG_INTERFACE: {
        if (!st._logPtr) st._logPtr = mod.addFunction((lvl, fmt) => { const m = readStr(fmt); (st.logs ||= []).push(m); }, "viii");
        poke32(dataPtr, st._logPtr); return true;
      }
      case E.SET_PIXEL_FORMAT: {
        const f = peek32(dataPtr);
        if (f === PIX.XRGB8888 || f === PIX.RGB565 || f === PIX._0RGB1555) { st.pixelFormat = f; return true; }
        return false;
      }
      case E.SET_SUPPORT_NO_GAME: return true;
      case E.GET_SYSTEM_DIRECTORY: case E.GET_SAVE_DIRECTORY: case E.GET_CONTENT_DIRECTORY:
        poke32(dataPtr, allocString("/")); return true;
      case E.GET_USERNAME: poke32(dataPtr, allocString("player")); return true;
      case E.GET_LANGUAGE: poke32(dataPtr, 0); return true;
      case E.GET_VARIABLE_UPDATE: u8()[dataPtr] = st.variablesUpdated ? 1 : 0; st.variablesUpdated = false; return true;
      case E.GET_VARIABLE: {
        const key = readStr(peek32(dataPtr));
        const v = st.coreVariables.get(key);
        if (!v) { poke32(dataPtr + 4, 0); return false; }
        if (v._ptr) mod._free(v._ptr);
        v._ptr = allocString(v.value);
        poke32(dataPtr + 4, v._ptr); return true;
      }
      case E.SET_VARIABLES: {
        let ptr = dataPtr;
        while (true) {
          const kP = peek32(ptr), dP = peek32(ptr + 4);
          if (!kP) break;
          const key = readStr(kP), desc = dP ? readStr(dP) : "";
          const semi = desc.indexOf("; ");
          const options = semi >= 0 ? desc.substring(semi + 2).split("|") : [];
          const prior = st.coreVariables.get(key);
          const value = prior && options.includes(prior.value) ? prior.value : options[0];
          st.coreVariables.set(key, { description: semi >= 0 ? desc.substring(0, semi) : desc, options, value });
          ptr += 8;
        }
        return true;
      }
      case E.GET_CORE_OPTIONS_VERSION: poke32(dataPtr, 0); return true;
      case E.SET_CORE_OPTIONS: case E.SET_CORE_OPTIONS_INTL: case E.SET_CORE_OPTIONS_V2: case E.SET_CORE_OPTIONS_V2_INTL:
        return true;
      case E.GET_INPUT_BITMASKS: return true;
      case E.GET_AUDIO_VIDEO_ENABLE: poke32(dataPtr, 7); return true;
      case E.SET_GEOMETRY: case E.SET_PERFORMANCE_LEVEL: case E.SET_MEMORY_MAPS:
      case E.SET_CONTROLLER_INFO: case E.SET_SUBSYSTEM_INFO: case E.SET_VARIABLE:
      case E.SET_SUPPORT_ACHIEVEMENTS: case E.SET_KEYBOARD_CALLBACK:
      case E.SET_INPUT_DESCRIPTORS:
        return true;
      case E.GET_PERF_INTERFACE: return false;
      default: return false;
    }
  }

  mod._retro_init();
  const si = mod._malloc(20); mod._retro_get_system_info(si);
  st.sysInfo = {
    name: readStr(peek32(si)), ver: readStr(peek32(si + 4)),
    exts: readStr(peek32(si + 8)),
    need_fullpath: !!peek8(si + 12), block: peek32(si + 16),
  };
  mod._free(si);

  // ---- load game ----
  // FCEUmm reports need_fullpath=true: it reads the ROM from the Emscripten
  // virtual filesystem via game_info.path and ignores game_info.data. So write
  // the bytes into Module.FS and pass data=0. For need_fullpath=false cores we
  // hand the heap pointer directly.
  const vfsPath = "/roms/" + romName;
  if (st.sysInfo.need_fullpath && mod.FS) {
    try { mod.FS.mkdir("/roms"); } catch {}
    mod.FS.writeFile(vfsPath, romBytes);
  }
  let dataPtr = 0;
  if (!st.sysInfo.need_fullpath) {
    dataPtr = mod._malloc(romBytes.length);
    u8().set(romBytes, dataPtr);
  }
  const pathPtr = allocString(st.sysInfo.need_fullpath ? vfsPath : romName);
  const infoPtr = mod._malloc(16);
  poke32(infoPtr + 0, pathPtr); poke32(infoPtr + 4, dataPtr); poke32(infoPtr + 8, dataPtr ? romBytes.length : 0); poke32(infoPtr + 12, 0);
  const ok = mod._retro_load_game(infoPtr);
  mod._free(infoPtr);
  if (!ok) { const logs=(st.logs||[]).join(" | "); const tr=(st.envTrace||[]).join(","); try { mod._retro_deinit(); } catch {} throw new Error("load false. sys="+JSON.stringify(st.sysInfo)+" log:[" + logs + "] env:[" + tr + "]"); }

  const av = mod._malloc(64); mod._retro_get_system_av_info(av);
  fbW = peek32(av) || 256; fbH = peek32(av + 4) || 240;
  avInfo.fps = mod.getValue(av + 24, "double") || 60;
  avInfo.sampleRate = mod.getValue(av + 32, "double") || 44100;
  mod._free(av);

  mod._retro_set_controller_port_device(0, 1);
  mod._retro_set_controller_port_device(1, 1);

  // restore SRAM if provided (RETRO_MEMORY_SAVE_RAM=2)
  if (sram) {
    const sPtr = mod._retro_get_memory_data(2), sSz = mod._retro_get_memory_size(2);
    if (sPtr && sSz) u8().set(sram.subarray(0, Math.min(sram.length, sSz)), sPtr);
  }
  mod._retro_reset();

  const api = {
    mod, avInfo,
    get geometry(){ return { w: fbW, h: fbH, format: st.pixelFormat }; },
    runFrame(){ mod._retro_run(); },
    button(name, down){
      const id = BUTTONS[name]; if (id === undefined) return;
      const w = st.inputPorts[0];
      if (down) w[0] |= (1 << id); else w[0] &= ~(1 << id);
    },
    setRgbaTarget(canvas){
      ctx2d = canvas.getContext("2d", { alpha:false });
      if (rgba32) this.blit();
      else ctx2d.fillRect(0,0,canvas.width,canvas.height);
    },
    blit(){
      if (!ctx2d) return;
      const cw = ctx2d.canvas.width, ch = ctx2d.canvas.height;
      if (!imgData || imgData.width !== cw || imgData.height !== ch) imgData = ctx2d.createImageData(cw, ch);
      const d32 = new Uint32Array(imgData.data.buffer);
      for (let y = 0; y < ch; y++) d32.fill(0xff000000, y*cw, y*cw+cw);
      if (rgba32) {
        const w = Math.min(fbW, cw), h = Math.min(fbH, ch);
        const oy = (ch - h) >> 1, ox = (cw - w) >> 1;
        for (let y = 0; y < h; y++) d32.set(rgba32.subarray(y*fbW, y*fbW+w), (y+oy)*cw + ox);
      }
      ctx2d.putImageData(imgData, 0, 0);
    },
    readFrame(){ return { pixels: rgbaBuf, w: fbW, h: fbH }; },
    audio: { available: audioAvailable, read: audioRead },
    saveRam(){ const p = mod._retro_get_memory_data(2), s = mod._retro_get_memory_size(2); return (p && s) ? new Uint8Array(mod.HEAPU8.buffer.slice(p, p + s)) : null; },
    unload(){ try { mod._retro_unload_game(); mod._retro_deinit(); } catch {} },
  };
  return api;
}

function decode(srcPtr, heap, w, h, pitch, dst32, format) {
  const src = heap; // little-endian
  const dst = dst32; // ABGR in memory => 0xAABBGGRR per u32 little-endian canvas
  for (let y = 0; y < h; y++) {
    const sRow = srcPtr + y * pitch, dRow = y * w;
    for (let x = 0; x < w; x++) {
      const s = sRow + x * (format === PIX.XRGB8888 ? 4 : 2);
      let r, g, b;
      if (format === PIX.XRGB8888) { b = src[s]; g = src[s+1]; r = src[s+2]; }
      else if (format === PIX.RGB565) {
        const px = src[s] | (src[s+1] << 8);
        const r5 = (px >> 11) & 0x1f, g6 = (px >> 5) & 0x3f, b5 = px & 0x1f;
        r = (r5 << 3) | (r5 >> 2); g = (g6 << 2) | (g6 >> 4); b = (b5 << 3) | (b5 >> 2);
      } else { // 0RGB1555
        const px = src[s] | (src[s+1] << 8);
        const r5 = (px >> 10) & 0x1f, g5 = (px >> 5) & 0x1f, b5 = px & 0x1f;
        r = (r5 << 3) | (r5 >> 2); g = (g5 << 3) | (g5 >> 2); b = (b5 << 3) | (b5 >> 2);
      }
      dst[dRow + x] = (255 << 24) | (b << 16) | (g << 8) | r;
    }
  }
}
