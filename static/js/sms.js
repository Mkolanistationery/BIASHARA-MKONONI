(function () {
  var sel = document.getElementById('rt');
  function upd() {
    document.getElementById('single').hidden = sel.value !== 'single';
    document.getElementById('custom').hidden = sel.value !== 'custom';
  }
  sel.addEventListener('change', upd); upd();
})();
