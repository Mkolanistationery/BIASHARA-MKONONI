(function () {
  var data = JSON.parse(document.getElementById('pdata').textContent);
  var canPrice = document.body.dataset.canPrice === '1';
  var csrf = document.querySelector('meta[name=csrf-token]').content;
  var cart = [];
  var $ = function (id) { return document.getElementById(id); };
  var money = function (n) { return Math.round(n).toLocaleString('en-US'); };
  function esc(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
  function findProduct(txt) {
    txt = (txt || '').trim().toLowerCase();
    if (!txt) return null;
    return data.find(function (p) { return p.name.toLowerCase() === txt || (p.barcode && p.barcode.toLowerCase() === txt); }) || null;
  }
  function sum() { var t = 0; cart.forEach(function (c) { t += c.price * c.qty; }); return t; }
  function render() {
    var tb = $('cart').querySelector('tbody'); tb.innerHTML = '';
    cart.forEach(function (it, i) {
      var tr = document.createElement('tr');
      tr.innerHTML = '<td>' + esc(it.name) + (it.pid ? '' : ' <span class="badge grey">mkono</span>') + '</td>' +
        '<td><input class="q" type="number" min="1" value="' + it.qty + '" data-i="' + i + '" data-k="qty" aria-label="Idadi"></td>' +
        '<td>' + ((canPrice || !it.pid) ? '<input type="number" min="1" value="' + it.price + '" data-i="' + i + '" data-k="price" aria-label="Bei">' : money(it.price)) + '</td>' +
        '<td class="num">' + money(it.price * it.qty) + '</td>' +
        '<td><button type="button" class="btn danger sm" data-del="' + i + '" aria-label="Ondoa">x</button></td>';
      tb.appendChild(tr);
    });
    $('empty').hidden = cart.length > 0;
    $('total').textContent = money(sum());
    $('save').disabled = cart.length === 0;
  }
  $('cart').addEventListener('input', function (e) {
    var i = e.target.dataset.i, k = e.target.dataset.k;
    if (i === undefined) return;
    cart[i][k] = Math.max(parseInt(e.target.value, 10) || 1, 1);
    $('total').textContent = money(sum());
    e.target.closest('tr').children[3].textContent = money(cart[i].price * cart[i].qty);
  });
  $('cart').addEventListener('click', function (e) {
    var b = e.target.closest('[data-del]'); if (!b) return;
    cart.splice(parseInt(b.dataset.del, 10), 1); render();
  });
  $('iname').addEventListener('input', function () {
    var p = findProduct(this.value);
    if (p) { $('iprice').value = p.price; $('ihint').textContent = 'Stoko: ' + p.stock; }
    else { $('ihint').textContent = this.value ? 'Haipo kwenye stoko: itaingia kama bidhaa ya mkono (weka bei).' : ''; }
  });
  function add() {
    var name = $('iname').value.trim(), qty = parseInt($('iqty').value, 10) || 1, price = parseInt($('iprice').value, 10) || 0;
    if (!name) return;
    var p = findProduct(name);
    if (p) {
      var ex = cart.find(function (c) { return c.pid === p.id; });
      if (ex) ex.qty += qty; else cart.push({ pid: p.id, name: p.name, qty: qty, price: p.price });
    } else {
      if (price <= 0) { $('ihint').textContent = 'Weka bei ya bidhaa hii.'; $('iprice').focus(); return; }
      cart.push({ pid: null, name: name, qty: qty, price: price });
    }
    $('iname').value = ''; $('iqty').value = 1; $('iprice').value = ''; $('ihint').textContent = '';
    render(); $('iname').focus();
  }
  $('add').addEventListener('click', add);
  $('iname').addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); add(); } });
  $('pay').addEventListener('change', function () { $('creditbox').hidden = this.value !== 'DENI'; });
  $('cust').addEventListener('change', function () { $('newcust').hidden = !!this.value; });
  $('save').addEventListener('click', function () {
    var btn = this; btn.disabled = true; $('err').hidden = true;
    var body = {
      items: cart.map(function (c) { return { product_id: c.pid, name: c.name, qty: c.qty, price: c.price }; }),
      payment_method: $('pay').value, customer_id: $('cust').value || null,
      customer_name: $('cname').value, customer_phone: $('cphone').value,
      paid: $('paid').value, due_date: $('due').value, send_sms: $('smsr').checked
    };
    fetch('/sales/save', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf }, body: JSON.stringify(body) })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
      .then(function (res) {
        if (res.ok && res.j.ok) { window.location = res.j.url; }
        else { $('err').textContent = res.j.error || 'Imeshindikana kuhifadhi.'; $('err').hidden = false; btn.disabled = false; }
      })
      .catch(function () { $('err').textContent = 'Hakuna mtandao. Jaribu tena.'; $('err').hidden = false; btn.disabled = false; });
  });
  render();
})();
