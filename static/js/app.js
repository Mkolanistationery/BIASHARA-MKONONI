document.addEventListener('submit', function (e) {
  var f = e.target;
  if (f.dataset && f.dataset.confirm && !window.confirm(f.dataset.confirm)) e.preventDefault();
});
document.addEventListener('click', function (e) {
  if (e.target.closest('#navtoggle')) document.body.classList.toggle('nav-open');
  if (e.target.closest('[data-print]')) window.print();
});
document.querySelectorAll('textarea[data-counter]').forEach(function (t) {
  var out = document.querySelector(t.dataset.counter);
  function upd() {
    var n = t.value.length, p = n <= 160 ? 1 : Math.ceil(n / 153);
    if (out) out.textContent = n + ' herufi, SMS ' + (n ? p : 0) + ' kwa kila mpokeaji';
  }
  t.addEventListener('input', upd); upd();
});
document.querySelectorAll('[data-toggle-target]').forEach(function (s) {
  var t = document.querySelector(s.dataset.toggleTarget);
  function upd() { if (t) t.hidden = s.value !== s.dataset.toggleValue; }
  s.addEventListener('change', upd); upd();
});
