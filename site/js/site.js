// SecretBroker website. No dependencies, no cookies, no analytics.
// The only request to another server is the one in loadRelease(): GitHub's public API, to find the latest installers.
(function () {
  'use strict';

  var REPO = 'xBofi/SecretBroker';
  var RELEASE_API = 'https://api.github.com/repos/' + REPO + '/releases/latest';
  var DOWNLOAD_PREFIX = 'https://github.com/' + REPO + '/releases/download/';
  var ASSETS = {
    windows: /^SecretBroker-Setup-(\d+\.\d+\.\d+)\.exe$/,
    linux: /^secretbroker_(\d+\.\d+\.\d+)_amd64\.deb$/,
    'macos-arm64': /^SecretBroker-(\d+\.\d+\.\d+)-macos-arm64\.pkg$/,
    'macos-x86_64': /^SecretBroker-(\d+\.\d+\.\d+)-macos-x86_64\.pkg$/
  };
  var root = document.documentElement;

  function each(selector, fn) { Array.prototype.forEach.call(document.querySelectorAll(selector), fn); }

  // ---------------------------------------------------------------- theme
  function currentTheme() {
    var set = root.getAttribute('data-theme');
    if (set) return set;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  each('.theme-toggle', function (button) {
    button.addEventListener('click', function () {
      var next = currentTheme() === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      try { localStorage.setItem('sb-theme', next); } catch (e) { /* not remembered */ }
    });
  });

  // ---------------------------------------------------------------- small menu
  each('.menu', function (menu) {
    document.addEventListener('click', function (event) { if (menu.open && !menu.contains(event.target)) menu.open = false; });
    document.addEventListener('keydown', function (event) { if (event.key === 'Escape' && menu.open) { menu.open = false; menu.querySelector('summary').focus(); } });
  });

  // ---------------------------------------------------------------- "on this page": mark where the reader is
  (function () {
    var links = {};
    each('.toc a[href^="#"]', function (a) { links[a.getAttribute('href').slice(1)] = a; });
    var ids = Object.keys(links);
    if (!ids.length || !('IntersectionObserver' in window)) return;
    var visible = {};
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) { visible[entry.target.id] = entry.isIntersecting; });
      var current = null;
      ids.forEach(function (id) { if (visible[id] && !current) current = id; });
      if (!current) return;
      ids.forEach(function (id) { links[id].classList.toggle('is-current', id === current); });
    }, { rootMargin: '-80px 0px -65% 0px' });
    ids.forEach(function (id) { var heading = document.getElementById(id); if (heading) observer.observe(heading); });
  })();

  // ---------------------------------------------------------------- copy buttons on commands
  each('pre[data-copy]', function (pre) {
    if (!navigator.clipboard) return;
    var button = document.createElement('button');
    button.type = 'button';
    button.className = 'btn sm copy-btn';
    button.textContent = pre.getAttribute('data-copy');
    button.addEventListener('click', function () {
      navigator.clipboard.writeText(pre.querySelector('code').textContent.trim()).then(function () {
        var label = button.textContent;
        button.textContent = pre.getAttribute('data-copied') || label;
        setTimeout(function () { button.textContent = label; }, 1600);
      });
    });
    pre.insertBefore(button, pre.firstChild);
  });

  // ---------------------------------------------------------------- downloads
  var texts = {};
  var textsNode = document.getElementById('dl-texts');
  if (textsNode) {
    try { texts = JSON.parse(textsNode.textContent); } catch (e) { texts = {}; }
  }
  if (!document.querySelector('[data-asset], [data-download]')) return;

  function detectSystem() {
    var asked = /[?&]os=(windows|linux|macos|mobile|other)\b/.exec(location.search);
    if (asked) return asked[1];
    var data = navigator.userAgentData;
    var platform = String((data && data.platform) || navigator.platform || '').toLowerCase();
    var agent = String(navigator.userAgent || '').toLowerCase();
    if (/android|iphone|ipad|ipod/.test(agent) || (platform === 'macintel' && navigator.maxTouchPoints > 1)) return 'mobile';
    if (platform.indexOf('win') === 0 || /windows/.test(agent)) return 'windows';
    if (platform.indexOf('mac') === 0 || /mac os x/.test(agent)) return 'macos';
    if (/cros/.test(agent)) return 'other';
    if (/linux|x11/.test(platform) || /linux/.test(agent)) return 'linux';
    return 'other';
  }

  function megabytes(bytes) { return Math.round(bytes / 1048576) + ' MB'; }
  function fill(template, values) {
    return String(template || '').replace(/\{(\w+)\}/g, function (all, key) { return values[key] == null ? all : values[key]; });
  }

  var system = detectSystem();
  var primaryKey = system === 'windows' ? 'windows' : system === 'linux' ? 'linux' : null;  // a Mac's processor is asked below
  var mainButton = document.querySelector('[data-download="main"]');
  var mainMeta = document.querySelector('[data-download="meta"]');
  var heroButton = document.querySelector('[data-download="hero"]');
  var status = document.querySelector('[data-download="status"]');

  function label() {
    if (system === 'windows') return texts.forWindows;
    if (system === 'linux') return texts.forLinux;
    if (system === 'macos') return texts.forMac;
    return null;
  }
  function markYours() {
    each('.dl-row', function (row) {
      var key = row.getAttribute('data-row');
      var yours = key === primaryKey || (system === 'macos' && !primaryKey && key.indexOf('macos') === 0);
      row.classList.toggle('is-yours', !!yours);
    });
  }
  function paintStatic() {
    var text = label();
    if (text) {
      if (mainButton) mainButton.querySelector('span').textContent = text;
      if (heroButton) heroButton.querySelector('span').textContent = text;
    }
    if (mainMeta && system === 'mobile') mainMeta.textContent = texts.mobile;
    if (mainMeta && system === 'macos') mainMeta.textContent = texts.macHint;
    markYours();
  }
  paintStatic();

  function applyRelease(release) {
    var found = {};
    (release.assets || []).forEach(function (asset) {
      Object.keys(ASSETS).forEach(function (key) {
        var match = ASSETS[key].exec(asset.name);
        var url = String(asset.browser_download_url || '');
        if (match && url.indexOf(DOWNLOAD_PREFIX) === 0) found[key] = { url: url, version: match[1], size: asset.size, name: asset.name };
      });
    });
    each('[data-asset]', function (link) {
      var asset = found[link.getAttribute('data-asset')];
      if (!asset) return;
      link.href = asset.url;
      var row = link.closest ? link.closest('.dl-row') : null;
      var size = row && row.querySelector('[data-size]');
      if (size) size.textContent = ' · ' + megabytes(asset.size);
    });
    var primary = primaryKey && found[primaryKey];
    if (primary) {
      [mainButton, heroButton].forEach(function (button) { if (button) button.href = primary.url; });
      if (mainMeta) mainMeta.textContent = fill(texts.meta, { version: primary.version, size: megabytes(primary.size), file: primary.name });
    }
    var any = found.windows || found.linux || found['macos-arm64'];
    each('[data-version]', function (node) { if (any) node.textContent = fill(texts.version, { version: any.version }); });
  }

  function loadRelease() {
    var cached = null;
    try { cached = JSON.parse(sessionStorage.getItem('sb-release') || 'null'); } catch (e) { cached = null; }
    if (cached && Date.now() - cached.at < 15 * 60 * 1000) { applyRelease(cached.release); return; }
    if (!window.fetch) return;
    var controller = 'AbortController' in window ? new AbortController() : null;
    var timer = setTimeout(function () { if (controller) controller.abort(); }, 8000);
    fetch(RELEASE_API, { headers: { Accept: 'application/vnd.github+json' }, credentials: 'omit', referrerPolicy: 'no-referrer', signal: controller ? controller.signal : undefined })
      .then(function (response) { if (!response.ok) throw new Error('HTTP ' + response.status); return response.json(); })
      .then(function (release) {
        var slim = { assets: (release.assets || []).map(function (a) { return { name: a.name, size: a.size, browser_download_url: a.browser_download_url }; }) };
        try { sessionStorage.setItem('sb-release', JSON.stringify({ at: Date.now(), release: slim })); } catch (e) { /* not cached */ }
        applyRelease(slim);
      })
      .catch(function () { if (status) { status.textContent = texts.offline; status.hidden = false; } })
      .then(function () { clearTimeout(timer); });
  }

  // Apple silicon or Intel: only Chromium browsers say. Otherwise both stay offered, with a hint.
  if (system === 'macos' && navigator.userAgentData && navigator.userAgentData.getHighEntropyValues) {
    navigator.userAgentData.getHighEntropyValues(['architecture']).then(function (values) {
      if (values.architecture === 'arm') primaryKey = 'macos-arm64';
      else if (values.architecture === 'x86') primaryKey = 'macos-x86_64';
      markYours();
      loadRelease();
    }, loadRelease);
  } else {
    loadRelease();
  }
})();
