// Runs before the page is drawn: the theme chosen with the header's toggle (or ?theme=light|dark), else the system's.
(function () {
  var root = document.documentElement;
  var theme = null;
  var asked = /[?&]theme=(light|dark)\b/.exec(location.search);
  if (asked) theme = asked[1];
  if (!theme) {
    try { theme = localStorage.getItem('sb-theme'); } catch (e) { /* storage blocked: follow the system */ }
  }
  if (theme === 'light' || theme === 'dark') root.setAttribute('data-theme', theme);
  root.classList.add('js');
})();
