// Front-end helpers for the AcmeShop storefront.
function showMessage() {
  const msg = decodeURIComponent(location.hash.slice(1));
  document.getElementById("banner").innerHTML = msg;
}

function showMessageSafe() {
  const msg = decodeURIComponent(location.hash.slice(1));
  document.getElementById("banner").textContent = msg;
}

window.addEventListener("hashchange", showMessage);
