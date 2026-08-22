/**
 * AQUA 多维度前端指纹采集库 v1.0
 * 采集维度：
 *   1. Canvas 指纹 (图像渲染差异)
 *   2. WebGL 指纹 (GPU/驱动信息)
 *   3. WebRTC 内网真实IP泄露
 *   4. AudioContext 指纹 (音频处理差异)
 *   5. 字体列表 (系统字体)
 *   6. 屏幕/浏览器基础信息
 *   7. 时区/语言
 *   8. 硬件并发数
 *   9. 触摸支持
 *  10. 插件列表
 *
 * 所有指纹组合后使用 SHA-256 哈希生成最终设备指纹
 */
(function () {
  'use strict';

  var FP = window.AQUAFingerprint = {};
  var _fpCache = null;

  // ========== 1. Canvas 指纹 ==========
  function getCanvasFingerprint() {
    try {
      var canvas = document.createElement('canvas');
      canvas.width = 280;
      canvas.height = 60;
      var ctx = canvas.getContext('2d');
      if (!ctx) return '';

      // 绘制文字
      ctx.textBaseline = 'top';
      ctx.font = '16px Arial';
      ctx.fillStyle = '#f60';
      ctx.fillRect(10, 2, 60, 20);
      ctx.fillStyle = '#069';
      ctx.fillText('AQUA Fingerprint 水印!', 4, 20);
      ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
      ctx.fillText('Canvas Fingerprint 测试!', 6, 38);

      // 绘制几何图形
      ctx.strokeStyle = '#f00';
      ctx.beginPath();
      ctx.arc(150, 30, 20, 0, Math.PI * 2, true);
      ctx.stroke();

      ctx.fillStyle = 'rgba(0, 0, 255, 0.3)';
      ctx.beginPath();
      ctx.arc(200, 25, 15, 0, Math.PI, false);
      ctx.fill();

      return canvas.toDataURL();
    } catch (e) {
      return '';
    }
  }

  // ========== 2. WebGL 指纹 (GPU/驱动) ==========
  function getWebGLFingerprint() {
    try {
      var canvas = document.createElement('canvas');
      var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return '';

      var debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      var vendor = debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : '';
      var renderer = debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : '';

      // 获取支持的扩展
      var extensions = gl.getSupportedExtensions() || [];

      // 获取 WebGL 参数
      var params = [
        gl.getParameter(gl.MAX_TEXTURE_SIZE),
        gl.getParameter(gl.MAX_VIEWPORT_DIMS).join(','),
        gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
        gl.getParameter(gl.MAX_COMBINED_TEXTURE_IMAGE_UNITS),
        gl.getParameter(gl.MAX_VERTEX_TEXTURE_IMAGE_UNITS),
        gl.getParameter(gl.MAX_VERTEX_ATTRIBS),
        gl.getParameter(gl.ALIASED_LINE_WIDTH_RANGE).join(','),
        gl.getParameter(gl.ALIASED_POINT_SIZE_RANGE).join(','),
        gl.getParameter(gl.MAX_VARYING_VECTORS),
        gl.getParameter(gl.SHADING_LANGUAGE_VERSION)
      ];

      return vendor + '|' + renderer + '|' + extensions.sort().join(',') + '|' + params.join('|');
    } catch (e) {
      return '';
    }
  }

  // ========== 3. WebRTC 内网真实IP ==========
  function getWebRTCIPs() {
    return new Promise(function (resolve) {
      var ips = [];
      var timeout = setTimeout(function () {
        resolve(ips);
      }, 3000);

      try {
        var RTCPeerConnection = window.RTCPeerConnection || window.mozRTCPeerConnection || window.webkitRTCPeerConnection;
        if (!RTCPeerConnection) {
          clearTimeout(timeout);
          resolve(ips);
          return;
        }

        var pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
        pc.createDataChannel('');

        pc.onicecandidate = function (e) {
          if (!e.candidate) {
            clearTimeout(timeout);
            resolve(ips);
            return;
          }
          var candidate = e.candidate.candidate;
          var ipRegex = /([0-9]{1,3}(\.[0-9]{1,3}){3})/;
          var match = ipRegex.exec(candidate);
          if (match && match[1]) {
            var ip = match[1];
            // 过滤公网IP（STUN服务器地址），只保留内网IP
            if (isPrivateIP(ip) && ips.indexOf(ip) === -1) {
              ips.push(ip);
            }
          }
        };

        pc.createOffer().then(function (offer) {
          return pc.setLocalDescription(offer);
        }).catch(function () {
          clearTimeout(timeout);
          resolve(ips);
        });
      } catch (e) {
        clearTimeout(timeout);
        resolve(ips);
      }
    });
  }

  function isPrivateIP(ip) {
    var parts = ip.split('.');
    if (parts.length !== 4) return false;
    var b1 = parseInt(parts[0], 10);
    var b2 = parseInt(parts[1], 10);
    // 10.x.x.x, 172.16-31.x.x, 192.168.x.x
    if (b1 === 10) return true;
    if (b1 === 172 && b2 >= 16 && b2 <= 31) return true;
    if (b1 === 192 && b2 === 168) return true;
    return false;
  }

  // ========== 4. AudioContext 指纹 ==========
  function getAudioFingerprint() {
    try {
      var AudioContext = window.AudioContext || window.webkitAudioContext;
      if (!AudioContext) return '';

      var ctx = new AudioContext();
      var oscillator = ctx.createOscillator();
      var analyser = ctx.createAnalyser();
      var gain = ctx.createGain();
      var scriptProcessor = ctx.createScriptProcessor(4096, 1, 1);

      gain.gain.value = 0; // 静音
      oscillator.type = 'triangle';
      oscillator.connect(analyser);
      analyser.connect(scriptProcessor);
      scriptProcessor.connect(gain);
      gain.connect(ctx.destination);
      oscillator.start(0);

      var audioData = [
        ctx.sampleRate,
        ctx.destination.maxChannelCount,
        oscillator.frequency.value,
        analyser.frequencyBinCount,
        analyser.fftSize,
        analyser.minDecibels,
        analyser.maxDecibels,
        analyser.smoothingTimeConstant
      ];

      oscillator.stop(0);
      scriptProcessor.disconnect();
      gain.disconnect();
      analyser.disconnect();
      oscillator.disconnect();
      ctx.close();

      return audioData.join('|');
    } catch (e) {
      return '';
    }
  }

  // ========== 5. 字体列表 ==========
  function getFontList() {
    var testFonts = [
      'Arial', 'Arial Black', 'Arial Narrow', 'Arial Unicode MS',
      'Calibri', 'Cambria', 'Cambria Math', 'Candara', 'Century Gothic',
      'Comic Sans MS', 'Consolas', 'Constantia', 'Corbel', 'Courier New',
      'Georgia', 'Impact', 'Lucida Console', 'Lucida Sans Unicode',
      'Microsoft Sans Serif', 'MS Gothic', 'MS Mincho', 'MS PGothic',
      'MS PMincho', 'MS Serif', 'Palatino Linotype', 'Segoe Print',
      'Segoe Script', 'Segoe UI', 'Segoe UI Light', 'Segoe UI Semibold',
      'Segoe UI Symbol', 'Tahoma', 'Times New Roman', 'Trebuchet MS',
      'Verdana', 'Wingdings', 'Wingdings 2', 'Wingdings 3',
      'SimSun', 'SimHei', 'Microsoft YaHei', 'FangSong', 'KaiTi',
      'NSimSun', 'STSong', 'STKaiti', 'STHeiti', 'STFangsong',
      'PingFang SC', 'PingFang TC', 'PingFang HK',
      'Hiragino Sans', 'Hiragino Kaku Gothic ProN',
      'Noto Sans CJK SC', 'Noto Sans CJK TC',
      'Helvetica', 'Helvetica Neue', 'Menlo', 'Monaco', 'Roboto',
      'Open Sans', 'Lato', 'Montserrat', 'Source Sans Pro',
      'Liberation Sans', 'Liberation Serif', 'Liberation Mono',
      'DejaVu Sans', 'DejaVu Serif', 'DejaVu Sans Mono',
      'FreeSans', 'FreeSerif', 'FreeMono',
      'Ubuntu', 'Ubuntu Mono', 'Droid Sans', 'Droid Serif', 'Droid Sans Mono'
    ];

    var canvas = document.createElement('canvas');
    canvas.width = 100;
    canvas.height = 100;
    var ctx = canvas.getContext('2d');
    if (!ctx) return [];

    var baseFonts = ['monospace', 'sans-serif', 'serif'];
    var available = [];

    for (var i = 0; i < testFonts.length; i++) {
      var detected = false;
      for (var j = 0; j < baseFonts.length; j++) {
        var baseWidth = measureText(ctx, 'mmmmmmmmmmlli', baseFonts[j]);
        var testWidth = measureText(ctx, 'mmmmmmmmmmlli', "'" + testFonts[i] + "'," + baseFonts[j]);
        if (baseWidth !== testWidth) {
          detected = true;
          break;
        }
      }
      if (detected) {
        available.push(testFonts[i]);
      }
    }
    return available;
  }

  function measureText(ctx, text, font) {
    ctx.font = '16px ' + font;
    return ctx.measureText(text).width;
  }

  // ========== 6. 屏幕/浏览器基础信息 ==========
  function getScreenInfo() {
    return {
      screenWidth: screen.width,
      screenHeight: screen.height,
      availWidth: screen.availWidth,
      availHeight: screen.availHeight,
      colorDepth: screen.colorDepth,
      pixelRatio: window.devicePixelRatio || 1,
      innerWidth: window.innerWidth,
      innerHeight: window.innerHeight,
      outerWidth: window.outerWidth,
      outerHeight: window.outerHeight
    };
  }

  // ========== 7. 时区/语言 ==========
  function getLocaleInfo() {
    return {
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      timezoneOffset: new Date().getTimezoneOffset(),
      language: navigator.language,
      languages: (navigator.languages || [navigator.language]).join(','),
      platform: navigator.platform,
      userAgent: navigator.userAgent,
      vendor: navigator.vendor,
      productSub: navigator.productSub,
      appVersion: navigator.appVersion,
      cpuClass: navigator.cpuClass || '',
      oscpu: navigator.oscpu || ''
    };
  }

  // ========== 8. 硬件并发 ==========
  function getHardwareInfo() {
    return {
      hardwareConcurrency: navigator.hardwareConcurrency || 0,
      deviceMemory: navigator.deviceMemory || 0,
      maxTouchPoints: navigator.maxTouchPoints || 0,
      touchSupport: ('ontouchstart' in window),
      cookieEnabled: navigator.cookieEnabled,
      doNotTrack: navigator.doNotTrack || 'unspecified',
      pdfViewer: navigator.pdfViewerEnabled || false
    };
  }

  // ========== 9. 插件列表 ==========
  function getPlugins() {
    try {
      var plugins = navigator.plugins || [];
      var list = [];
      for (var i = 0; i < plugins.length; i++) {
        list.push(plugins[i].name);
      }
      return list.sort();
    } catch (e) {
      return [];
    }
  }

  // ========== 哈希函数 (SHA-256 via SubtleCrypto) ==========
  async function sha256(message) {
    try {
      var msgBuffer = new TextEncoder().encode(message);
      var hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
      var hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
    } catch (e) {
      // 回退：简单哈希
      return simpleHash(message);
    }
  }

  function simpleHash(str) {
    var hash = 0;
    for (var i = 0; i < str.length; i++) {
      var chr = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + chr;
      hash |= 0;
    }
    return Math.abs(hash).toString(16);
  }

  // ========== 主采集函数 ==========
  FP.collect = async function () {
    if (_fpCache) return _fpCache;

    // 收集同步数据
    var canvasFp = getCanvasFingerprint();
    var webglFp = getWebGLFingerprint();
    var audioFp = getAudioFingerprint();
    var fonts = getFontList();
    var screenInfo = getScreenInfo();
    var localeInfo = getLocaleInfo();
    var hardwareInfo = getHardwareInfo();
    var plugins = getPlugins();

    // 收集异步数据 (WebRTC)
    var webrtcIPs = [];
    try {
      webrtcIPs = await getWebRTCIPs();
    } catch (e) {
      // WebRTC 不可用
    }

    // 组合所有指纹
    var raw = [
      canvasFp.substring(0, 200),
      webglFp.substring(0, 300),
      audioFp,
      fonts.sort().join(','),
      JSON.stringify(screenInfo),
      JSON.stringify(localeInfo),
      JSON.stringify(hardwareInfo),
      plugins.join(','),
      webrtcIPs.sort().join(',')
    ].join('|||');

    // 哈希
    var hash = await sha256(raw);
    _fpCache = hash;
    return hash;
  };

  // 获取缓存的指纹
  FP.get = function () {
    return _fpCache;
  };

  // 重置缓存（强制重新采集）
  FP.reset = function () {
    _fpCache = null;
  };

  // 自动采集并注入到请求头
  FP.init = async function () {
    try {
      var fp = await FP.collect();
      if (fp && window.API) {
        // 修改 API 对象的 request 方法，自动注入设备指纹
        var originalRequest = window.API.request;
        window.API.request = async function (method, url, body) {
          var opts = { method: method, credentials: 'same-origin', headers: {} };
          opts.headers['X-Device-Fingerprint'] = fp;
          if (body !== undefined && body !== null) {
            opts.headers['Content-Type'] = 'application/json';
            opts.body = JSON.stringify(body);
          }
          var resp;
          try {
            resp = await fetch(url, opts);
          } catch (e) {
            throw { message: '网络请求失败', type: 'network_error', status: 0 };
          }
          if (resp.status === 401) {
            var cur = window.location.pathname;
            var isAuthPage = cur === '/login' || cur === '/register';
            var isAuthAPI = url.indexOf('/api/auth/login') === 0 || url.indexOf('/api/auth/register') === 0;
            if (!isAuthPage && !isAuthAPI) {
              window.location.href = '/login?redirect=' + encodeURIComponent(cur);
              throw { message: '未登录', type: 'auth_required', status: 401 };
            }
          }
          var ct = resp.headers.get('content-type') || '';
          var data = null;
          if (ct.includes('application/json')) {
            data = await resp.json();
          } else {
            var txt = await resp.text();
            try { data = JSON.parse(txt); } catch (e) { data = txt; }
          }
          if (!resp.ok) {
            var errMsg = (data && data.error && data.error.message) || ('请求失败 (' + resp.status + ')');
            var errType = (data && data.error && data.error.type) || 'request_error';
            throw { message: errMsg, type: errType, status: resp.status, data: data };
          }
          return data;
        };
      }
      return fp;
    } catch (e) {
      console.warn('AQUA Fingerprint: 采集失败', e);
      return '';
    }
  };
})();