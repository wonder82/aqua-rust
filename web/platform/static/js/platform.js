/* JHRY公益 平台共享脚本 - vanilla JS */
(function (window) {
  'use strict';

  // ============ HTML 转义 ============
  function escapeHtml(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // ============ 复制到剪贴板 ============
  async function copyToClipboard(text) {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch (e) { /* 回退 */ }
    // 回退方案
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    ta.style.top = '0';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    ta.setSelectionRange(0, ta.value.length);
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    document.body.removeChild(ta);
    return ok;
  }

  // ============ API 封装 ============
  const API = {
    async request(method, url, body) {
      const opts = { method, credentials: 'same-origin', headers: {} };
      if (['POST','PUT','PATCH','DELETE'].includes(method.toUpperCase())) {
        const m = document.cookie.match(/(?:^|;\s*)admin_csrf=([^;]+)/);
        if (m) opts.headers['X-CSRF-Token'] = decodeURIComponent(m[1]);
      }
      if (body !== undefined && body !== null) {
        opts.headers['Content-Type'] = 'application/json';
        opts.body = JSON.stringify(body);
      }
      let resp;
      try {
        resp = await fetch(url, opts);
      } catch (e) {
        throw { message: '网络请求失败', type: 'network_error', status: 0 };
      }
      // 401 处理：仅对非登录/注册/管理接口跳转登录页
      // 登录/注册接口返回 401 表示"密码错误"或"凭证无效"，不应跳转
      // /api/admin/* 的 401 交由 admin.html 自行处理（回到登录表单），不自动跳转用户登录页
      if (resp.status === 401) {
        var cur = window.location.pathname;
        var isAuthPage = cur === '/login' || cur === '/register';
        var isAuthAPI = url.indexOf('/api/auth/login') === 0 || url.indexOf('/api/auth/register') === 0 || url.indexOf('/api/admin/') === 0;
        if (!isAuthPage && !isAuthAPI) {
          window.location.href = '/login?redirect=' + encodeURIComponent(cur);
          throw { message: '未登录', type: 'auth_required', status: 401 };
        }
        // 登录/注册接口的 401，继续解析错误响应体
      }
      const ct = resp.headers.get('content-type') || '';
      let data = null;
      if (ct.includes('application/json')) {
        data = await resp.json();
      } else {
        const txt = await resp.text();
        try { data = JSON.parse(txt); } catch (e) { data = txt; }
      }
      if (!resp.ok) {
        const errMsg = (data && data.error && data.error.message) || ('请求失败 (' + resp.status + ')');
        const errType = (data && data.error && data.error.type) || 'request_error';
        throw { message: errMsg, type: errType, status: resp.status, data };
      }
      return data;
    },
    get(url) { return this.request('GET', url); },
    post(url, body) { return this.request('POST', url, body); },
    put(url, body) { return this.request('PUT', url, body); },
    del(url) { return this.request('DELETE', url); },
    upload(url, formData) {
      return fetch(url, { method: 'POST', body: formData, credentials: 'include' })
        .then(function (r) {
          if (!r.ok) {
            return r.json().then(function (d) { throw new Error(d.message || d.error || 'HTTP ' + r.status); });
          }
          return r.json().then(function (d) {
            if (d.code === 0) return d.data;
            throw new Error(d.message || d.error || '上传失败');
          });
        });
    },
  };

  // ============ Toast 通知系统 ============
  let toastContainer = null;
  function getToastContainer() {
    if (!toastContainer) {
      toastContainer = document.createElement('div');
      toastContainer.className = 'toast-container';
      document.body.appendChild(toastContainer);
    }
    return toastContainer;
  }
  const Toast = {
    show(msg, type, duration) {
      type = type || 'info';
      duration = duration || 3000;
      const el = document.createElement('div');
      el.className = 'toast ' + type;
      el.textContent = msg;
      getToastContainer().appendChild(el);
      setTimeout(function () {
        el.style.opacity = '0';
        el.style.transform = 'translateX(100%)';
        el.style.transition = 'all .2s';
        setTimeout(function () { el.remove(); }, 200);
      }, duration);
    },
    success(msg, d) { this.show(msg, 'success', d); },
    error(msg, d) { this.show(msg, 'error', d || 4000); },
    warn(msg, d) { this.show(msg, 'warn', d); },
    info(msg, d) { this.show(msg, 'info', d); },
  };

  // ============ Modal 模态框 ============
  const Modal = {
    show(opts) {
      const o = opts || {};
      const overlay = document.createElement('div');
      overlay.className = 'modal-overlay';
      const modal = document.createElement('div');
      modal.className = 'modal';
      modal.style.position = 'relative';
      let html = '';
      if (o.title) html += '<div class="modal-title">' + escapeHtml(o.title) + '</div>';
      // 始终创建 modal-body（body 或 bodyNode 都需要它）
      html += '<div class="modal-body">';
      if (o.body !== undefined) html += typeof o.body === 'string' ? o.body : '';
      html += '</div>';
      html += '<div class="modal-footer">';
      if (o.cancelText !== null) html += '<button class="btn modal-cancel">' + escapeHtml(o.cancelText || '取消') + '</button>';
      if (o.confirmText !== null) html += '<button class="btn btn-primary modal-confirm">' + escapeHtml(o.confirmText || '确定') + '</button>';
      html += '</div>';
      modal.innerHTML = html;
      // 插入自定义 body 节点
      if (o.bodyNode) {
        const bodyEl = modal.querySelector('.modal-body');
        if (bodyEl) bodyEl.innerHTML = '';
        bodyEl.appendChild(o.bodyNode);
      }
      overlay.appendChild(modal);
      overlay.addEventListener('click', function (e) {
        if (e.target === overlay) {
          if (o.onCancel) o.onCancel();
          Modal.close(overlay);
        }
      });
      const cancelBtn = modal.querySelector('.modal-cancel');
      const confirmBtn = modal.querySelector('.modal-confirm');
      if (cancelBtn) cancelBtn.onclick = function () {
        if (o.onCancel) o.onCancel();
        Modal.close(overlay);
      };
      if (confirmBtn) confirmBtn.onclick = function () {
        if (o.onConfirm) {
          var r = o.onConfirm(modal);
          if (r === false) return; // 显式返回 false 阻止关闭
          // 如果返回 Promise，等待完成再关闭（失败则不关闭）
          if (r && typeof r.then === 'function') {
            confirmBtn.disabled = true;
            confirmBtn.textContent = '处理中...';
            r.then(function () {
              Modal.close(overlay);
            }).catch(function () {
              confirmBtn.disabled = false;
              confirmBtn.textContent = o.confirmText || '确定';
            });
            return;
          }
        }
        Modal.close(overlay);
      };
      document.body.appendChild(overlay);
      return overlay;
    },
    confirm(opts) {
      return new Promise(function (resolve) {
        const o = typeof opts === 'string' ? { message: opts } : (opts || {});
        Modal.show({
          title: o.title || '确认操作',
          body: '<p>' + escapeHtml(o.message || '') + '</p>',
          confirmText: o.confirmText || '确定',
          cancelText: o.cancelText || '取消',
          onConfirm: function () { resolve(true); },
          onCancel: function () { resolve(false); },
        });
      });
    },
    close(overlay) {
      if (overlay && overlay.parentNode) overlay.remove();
    },
  };

  // ============ Theme 主题切换 ============
  var _themeMem = 'light';
  const Theme = {
    get() {
      try { return localStorage.getItem('theme') || _themeMem; } catch (e) { return _themeMem; }
    },
    set(theme) {
      _themeMem = theme;
      try { localStorage.setItem('theme', theme); } catch (e) {}
      document.documentElement.setAttribute('data-theme', theme);
      this.updateIcon();
    },
    toggle() { this.set(this.get() === 'dark' ? 'light' : 'dark'); },
    init() {
      const t = this.get();
      document.documentElement.setAttribute('data-theme', t);
      this.updateIcon();
      // 延迟更新图标：navbar 由页面内联脚本异步渲染，确保按钮存在后再设置图标
      setTimeout(() => this.updateIcon(), 0);
      setTimeout(() => this.updateIcon(), 150);
    },
    updateIcon() {
      const dark = this.get() === 'dark';
      // 主题切换图标：暗色用月亮，亮色用太阳
      const moonSvg = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
      const sunSvg = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>';
      document.querySelectorAll('[data-theme-toggle]').forEach(function (el) {
        el.innerHTML = dark ? moonSvg : sunSvg;
      });
    },
  };

  // ============ Fmt 格式化函数 ============
  const Fmt = {
    number(n) {
      n = Number(n) || 0;
      if (n >= 1e9) return (n / 1e9).toFixed(2) + 'B';
      if (n >= 1e6) return (n / 1e6).toFixed(2) + 'M';
      if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
      return String(n);
    },
    full(n) { return (Number(n) || 0).toLocaleString('en-US'); },
    latency(ms) {
      ms = Number(ms) || 0;
      if (!ms) return '0'; // 空值显示 0
      if (ms < 1) return ms.toFixed(2) + 'ms';
      if (ms < 1000) return Math.round(ms) + 'ms';
      return (ms / 1000).toFixed(2) + 's';
    },
    timeAgo(date) {
      if (!date) return '-';
      // 兼容毫秒与秒级时间戳（后端 epoch 秒 *1000；<1e12 视为秒，修复 1970 显示问题）
      if (typeof date === 'number' && date < 1e12) date = date * 1000;
      const d = new Date(date);
      if (isNaN(d.getTime())) return '-';
      const diff = (Date.now() - d.getTime()) / 1000;
      if (diff < 60) return '刚刚';
      if (diff < 3600) return Math.floor(diff / 60) + '分钟前';
      if (diff < 86400) return Math.floor(diff / 3600) + '小时前';
      if (diff < 2592000) return Math.floor(diff / 86400) + '天前';
      return d.toLocaleDateString('zh-CN');
    },
    time(date) {
      if (!date) return '-';
      // 兼容毫秒与秒级时间戳（后端 epoch 秒 *1000；<1e12 视为秒）
      if (typeof date === 'number' && date < 1e12) date = date * 1000;
      const d = new Date(date);
      if (isNaN(d.getTime())) return '-';
      const pad = function (n) { return n < 10 ? '0' + n : n; };
      return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
        ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
    },
    status(s) {
      const map = {
        success: ['success', '成功'],
        error: ['danger', '失败'],
        active: ['success', '活跃'],
        revoked: ['warning', '已停用'],
        pending: ['warning', '待处理'],
        banned: ['danger', '已封禁'],
        normal: ['primary', '正常'],
      };
      const m = map[s] || ['', s || '-'];
      return '<span class="tag ' + m[0] + '">' + escapeHtml(m[1]) + '</span>';
    },
    httpStatus(code) {
      code = Number(code) || 0;
      if (code >= 200 && code < 300) return '<span class="tag success">' + code + '</span>';
      if (code >= 300 && code < 400) return '<span class="tag primary">' + code + '</span>';
      if (code >= 400 && code < 500) return '<span class="tag warning">' + code + '</span>';
      if (code >= 500) return '<span class="tag danger">' + code + '</span>';
      return '<span class="tag">' + code + '</span>';
    },
  };

  // ============ 分页器 ============
  function renderPagination(container, total, page, pageSize, onChange) {
    container.innerHTML = '';
    container.className = 'pagination';
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    page = Math.min(Math.max(1, page), totalPages);
    if (totalPages <= 1) return;

    const mkBtn = function (text, p, disabled, active) {
      const btn = document.createElement('button');
      btn.innerHTML = text;
      if (disabled) btn.disabled = true;
      if (active) btn.classList.add('active');
      if (!disabled && !active) btn.onclick = function () { onChange(p); };
      return btn;
    };

    container.appendChild(mkBtn('上一页', page - 1, page <= 1, false));
    // 页码显示逻辑
    let start = Math.max(1, page - 2);
    let end = Math.min(totalPages, start + 4);
    if (end - start < 4) start = Math.max(1, end - 4);
    if (start > 1) {
      container.appendChild(mkBtn('1', 1, false, page === 1));
      if (start > 2) container.appendChild(document.createTextNode(' ... '));
    }
    for (let i = start; i <= end; i++) {
      container.appendChild(mkBtn(String(i), i, false, i === page));
    }
    if (end < totalPages) {
      if (end < totalPages - 1) container.appendChild(document.createTextNode(' ... '));
      container.appendChild(mkBtn(String(totalPages), totalPages, false, page === totalPages));
    }
    container.appendChild(mkBtn('下一页', page + 1, page >= totalPages, false));
  }

  // ============ Loader 加载状态 ============
  const Loader = {
    show(target) {
      const t = target || document.body;
      // 移除已有
      const old = t.querySelector('.loader-overlay');
      if (old) return;
      if (getComputedStyle(t).position === 'static') t.style.position = 'relative';
      const overlay = document.createElement('div');
      overlay.className = 'loader-overlay';
      overlay.innerHTML = '<div class="spinner"></div>';
      t.appendChild(overlay);
    },
    hide(target) {
      const t = target || document.body;
      const overlay = t.querySelector('.loader-overlay');
      if (overlay) overlay.remove();
    },
  };

  // ============ 登录状态检查 ============
  // 缓存当前登录用户，供 renderConsoleSidebar 等读取
  let _currentUser = null;
  // 静默检查登录态（不跳转），成功则填充 _currentUser，失败不阻塞页面
  async function checkAuth() {
    try {
      const resp = await fetch('/api/user/profile', { credentials: 'same-origin' });
      if (resp.ok) {
        const user = await resp.json();
        // profile 返回 user_id，统一补充 id 字段供前端登录态判断
        if (user && !user.id && user.user_id) user.id = user.user_id;
        _currentUser = user;
        return user;
      }
    } catch (e) { /* 忽略网络错误 */ }
    return null;
  }
  // 异步检查登录状态：调用 GET /api/user/profile
  // 仅 401 时跳转登录页，其他错误（502/500/网络错误）不跳转，避免登录循环
  async function requireAuth() {
    try {
      const resp = await fetch('/api/user/profile', { credentials: 'same-origin' });
      if (resp.status === 401) {
        // 明确未登录，跳转登录页（携带当前页面路径，登录后返回）
        const cur = window.location.pathname + window.location.search;
        window.location.href = '/login?redirect=' + encodeURIComponent(cur);
        return null;
      }
      if (!resp.ok) {
        // 服务器错误（502/500等），不跳转，返回 null 让页面自行处理
        console.error('Profile API error:', resp.status);
        return null;
      }
      const user = await resp.json();
      if (user && !user.id && user.user_id) user.id = user.user_id;
      _currentUser = user;
      return user;
    } catch (e) {
      // 网络错误（服务重启等），不跳转，避免登录循环
      console.error('Network error checking auth:', e);
      return null;
    }
  }

  // ============ 退出登录 ============
  async function logout() {
    try { await API.post('/api/auth/logout'); } catch (e) { /* 忽略 */ }
    window.location.href = '/login';
  }

  // ============ 公共导航栏渲染（公开页面用） ============
  function renderPublicNavbar(active) {
    const links = [
      { href: '/', label: '首页', key: 'home' },
      { href: '/models', label: '模型', key: 'models' },
      { href: '/docs', label: 'API文档', key: 'docs' },
    ];
    let html = '<nav class="navbar"><div class="navbar-inner">';
    html += '<div class="navbar-brand"><a href="/" class="brand-logo"><span class="brand-name">JHRY</span><span class="brand-tag">公益</span></a></div>';
    html += '<div class="navbar-links">';
    links.forEach(function (l) {
      const cls = active === l.key ? ' style="color:var(--text-primary)"' : '';
      const color = l.warn ? ' style="color:var(--accent-warning)"' : (l.primary ? ' style="color:var(--accent-primary)"' : cls);
      html += '<a href="' + l.href + '"' + color + '>' + l.label + '</a>';
    });
    html += '</div>';
    html += '<div class="navbar-actions">';
    html += '<button class="icon-btn" data-theme-toggle title="切换主题" onclick="Theme.toggle()"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg></button>';
    // 已登录显示"控制台/退出"两按钮，未登录显示"登录/注册"
    if (_currentUser && _currentUser.id) {
      html += '<a href="/console" class="btn btn-sm btn-primary">' + Icons.shield + ' 控制台</a>';
      html += '<a href="https://qm.qq.com/q/your-group" class="btn btn-sm" target="_blank">' + Icons.chat + ' QQ群</a>';
      html += '<button class="btn btn-sm btn-ghost" onclick="logout()">' + Icons.logout + ' 退出</button>';
    } else {
      html += '<a href="/login" class="btn btn-sm">登录</a>';
      html += '<a href="/register" class="btn btn-sm btn-primary">注册</a>';
    }
    html += '</div></div></nav>';
    return html;
  }

  function renderFooter() {
    return '<footer class="footer">' +
      '<div class="footer-brand"><span>JHRY</span> 公益 · 免费 AI 模型平台</div>' +
      '<div class="footer-links">' +
        '<a href="/">首页</a>' +
        '<a href="/models">模型列表</a>' +
        '<a href="/docs">API文档</a>' +
        '<a href="/console">控制台</a>' +
      '</div>' +
      '<div class="footer-friends" style="margin-top:8px;font-size:12px;color:var(--text-muted)">' +
        '<span style="opacity:.7">友情链接：</span>' +
        '<a href="https://cloudagnetnew.nsdmc.top/" target="_blank" rel="noopener" style="color:var(--text-secondary);text-decoration:none">CloudAgnet</a>' +
        '<a href="https://qm.qq.com/q/your-group" target="_blank" style="color:var(--text-secondary);text-decoration:none">QQ交流群</a>' +
      '</div>' +
      '<div class="footer-copy">© 2026 JHRY公益 · 免费 AI 模型平台</div>' +
    '</footer>';
  }

  // ============ 公共模型加载函数（多级降级） ============
  // 用法: AquaPlatform.loadModels(function(models) { ... 渲染下拉框 ... })
  function loadModels(callback) {
    var GATEWAY = 'https://api.ltzy.top';

    function doFetch(url, label) {
      return fetch(url)
        .then(function(r) {
          if (!r.ok) throw new Error(label + ' 返回 ' + r.status);
          return r.json();
        })
        .then(function(data) {
          if (data && Array.isArray(data.data)) {
            var models = [];
            data.data.forEach(function(m) {
              if (!m || !m.id) return;
              models.push(m);
            });
            if (models.length) { callback(null, models); return; }
            throw new Error(label + ' 返回空列表');
          }
          throw new Error(label + ' 无数据');
        });
    }

    doFetch('/v1/models', '平台')
      .catch(function(err1) {
        console.warn('AquaPlatform: 平台请求失败(' + err1.message + ')，降级网关...');
        return doFetch(GATEWAY + '/v1/models', '网关');
      })
      .catch(function(err2) {
        console.error('AquaPlatform: 全部请求失败: ' + err2.message);
        callback(new Error(err2.message), null);
      });
  }

  // ============ 控制台侧边栏 ============
  // 根据当前页面标识生成侧边栏并注入到 #app-sidebar 元素中
  function renderConsoleSidebar(activePage) {
    const user = _currentUser || {};
    const username = user.username || '用户';
    const email = user.email || '-';
    const initial = (username ? username[0] : 'U').toUpperCase();
    // 导航项
    const items = [
      { href: '/console', label: '概览', key: 'overview' },
      { href: '/console/keys', label: 'API密钥', key: 'keys' },
      { href: '/console/models', label: '模型列表', key: 'models' },
      { href: '/console/capabilities', label: '能力详情', key: 'capabilities' },
      { href: '/console/metrics', label: '模型监控', key: 'metrics' },
      { href: '/console/docs', label: 'API文档', key: 'docs' },
      { href: '/console/stats', label: '用量监视', key: 'stats' },
      { href: '/console/rank', label: '排行榜', key: 'rank', icon: '<svg viewBox="0 0 24 24" style="width:13px;height:13px;vertical-align:-2px;margin-right:4px;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round"><path d="M6 3h12v4a4 4 0 01-4 4h-4a4 4 0 01-4-4V3z"/><path d="M6 7H4a2 2 0 010-4h2"/><path d="M18 7h2a2 2 0 100-4h-2"/><rect x="8" y="11" width="8" height="2" rx="1"/><rect x="10" y="13" width="4" height="8" rx="1"/></svg>' },
      { href: '/console/logs', label: '请求日志', key: 'logs' },
      { href: '/console/settings', label: '设置', key: 'settings' },
    ];
    let html = '';
    html += '<div class="sidebar-user">';
    html += '<div class="sidebar-avatar">' + escapeHtml(initial) + '</div>';
    html += '<div class="sidebar-user-info">';
    html += '<div class="sidebar-user-name">' + escapeHtml(username) + '</div>';
    html += '<div class="sidebar-user-email">' + escapeHtml(email) + '</div>';
    html += '</div></div>';
    html += '<nav class="sidebar-nav">';
    items.forEach(function (it) {
      const cls = activePage === it.key ? 'nav-item active' : 'nav-item';
      const labelHtml = it.icon ? it.icon + escapeHtml(it.label) : escapeHtml(it.label);
      html += '<a href="' + it.href + '" class="' + cls + '">' + labelHtml + '</a>';
    });
    html += '</nav>';
    html += '<div class="sidebar-footer">';

    html += '<button class="nav-item" onclick="logout()">退出登录</button>';
    html += '</div>';
    // 注入到页面侧边栏容器
    const container = document.getElementById('app-sidebar');
    if (container) {
      container.innerHTML = html;
      container.style.display = 'flex'; // 确保可见
    } else {
      console.error('renderConsoleSidebar: #app-sidebar container not found');
    }

    // 移动端：注入汉堡菜单按钮到导航栏 + 遮罩层
    initMobileSidebar();

    return html;
  }

  // 移动端侧边栏切换
  function initMobileSidebar() {
    // 避免重复注入
    if (document.getElementById('sidebar-toggle-btn')) return;
    if (document.getElementById('sidebar-overlay')) return;

    const navbar = document.querySelector('.navbar .navbar-inner');
    const sidebar = document.getElementById('app-sidebar');
    if (!navbar || !sidebar) return;

    const NAV_ICONS = {
      open: '<svg viewBox="0 0 24 24" style="width:18px;height:18px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round"><path d="M3 6h18"/><path d="M3 12h18"/><path d="M3 18h18"/></svg>',
      close: '<svg viewBox="0 0 24 24" style="width:18px;height:18px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round"><path d="M7 7l10 10"/><path d="M17 7l-10 10"/></svg>'
    };
    // 汉堡按钮
    const toggleBtn = document.createElement('button');
    toggleBtn.id = 'sidebar-toggle-btn';
    toggleBtn.className = 'sidebar-toggle';
    toggleBtn.innerHTML = NAV_ICONS.open;
    toggleBtn.title = '菜单';
    toggleBtn.onclick = function(e) {
      e.stopPropagation();
      const isOpen = sidebar.classList.toggle('open');
      toggleBtn.innerHTML = isOpen ? NAV_ICONS.close : NAV_ICONS.open;
      const overlay = document.getElementById('sidebar-overlay');
      if (overlay) overlay.classList.toggle('show', isOpen);
    };
    navbar.insertBefore(toggleBtn, navbar.firstChild);

    // 遮罩层
    const overlay = document.createElement('div');
    overlay.id = 'sidebar-overlay';
    overlay.className = 'sidebar-overlay';
    overlay.onclick = function() {
      sidebar.classList.remove('open');
      toggleBtn.innerHTML = NAV_ICONS.open;
      overlay.classList.remove('show');
    };
    document.body.appendChild(overlay);
  }

  // ============ 手绘 SVG 图标库（全站统一，不使用 emoji） ============
  const Icons = {
    pen: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><path d="M17 3a2.8 2.8 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>',
    folder: '<svg viewBox="0 0 24 24" width="34" height="34" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>',
    user: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
    clock: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',
    eye: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>',
    chat: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/></svg>',
    heart: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>',
    star: '<svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round" style="vertical-align:-2px"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>',
    flag: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/></svg>',
    mail: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M22 7l-10 6L2 7"/></svg>',
    bell: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>',
    key: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>',
    alert: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    search: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
    chart: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><path d="M3 3v18h18"/><path d="M7 14l4-4 3 3 5-6"/></svg>',
    shield: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    logout: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>',
    send: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>',
    back: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>',
    doc: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><line x1="8" y1="17" x2="16" y2="17"/><line x1="8" y1="13" x2="13" y2="13"/></svg>',
    reply: '<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><polyline points="9 17 4 12 9 7"/><path d="M20 18v-2a4 4 0 0 0-4-4H4"/></svg>',
    inbox: '<svg viewBox="0 0 24 24" width="34" height="34" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/></svg>',
  };

  // ============ 登录态感知导航挂载 ============
  // 先渲染默认态；登录态检查完成后自动重渲染（已登录 → 显示 控制台/退出）
  function mountPublicNavbar(active, containerId) {
    const id = containerId || 'navbar';
    const el = document.getElementById(id);
    if (!el) return;
    const render = function () { el.innerHTML = renderPublicNavbar(active); };
    render();
    if (!window.__authChecked) {
      window.__authChecked = true;
      checkAuth().then(function () { render(); }).catch(function () {});
    }
  }

  // ============ 初始化 ============
  Theme.init();

  // 导出
  window.AquaPlatform = {
    escapeHtml: escapeHtml,
    copyToClipboard: copyToClipboard,
    API: API,
    Toast: Toast,
    Modal: Modal,
    Theme: Theme,
    Fmt: Fmt,
    Icons: Icons,
    renderPagination: renderPagination,
    Loader: Loader,
    requireAuth: requireAuth,
    checkAuth: checkAuth,
    logout: logout,
    loadModels: loadModels,
    renderPublicNavbar: renderPublicNavbar,
    mountPublicNavbar: mountPublicNavbar,
    renderFooter: renderFooter,
    renderConsoleSidebar: renderConsoleSidebar,
  };
  // 便捷全局别名
  window.API = API;
  window.Toast = Toast;
  window.Modal = Modal;
  window.Theme = Theme;
  window.Fmt = Fmt;
  window.Icons = Icons;
  window.escapeHtml = escapeHtml;
  window.copyToClipboard = copyToClipboard;
  window.renderPagination = renderPagination;
  window.Loader = Loader;
  window.requireAuth = requireAuth;
  window.logout = logout;
})(window);
