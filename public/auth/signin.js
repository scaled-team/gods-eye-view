// Top level: a plain redirect through SysOp. Framed (Delegate V2): SysOp and
// Google refuse to render in a frame, so sign in through a popup and redeem the
// code it posts back, bound to a nonce that never leaves this frame.
const button = document.getElementById('signin');
const status = document.getElementById('status');
const framed = (() => {
  try {
    return window.self !== window.top;
  } catch {
    return true;
  }
})();
const returnTo = location.pathname.startsWith('/auth/') ? '/' : location.pathname + location.search;

function randomNonce() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

button.addEventListener('click', () => {
  if (!framed) {
    location.assign(`/api/auth/login?return=${encodeURIComponent(returnTo)}`);
    return;
  }
  const nonce = randomNonce();
  const popup = window.open(`/api/auth/login?embed=${nonce}`, 'godseye-signin', 'popup,width=520,height=680');
  if (!popup) {
    status.textContent = 'Allow pop-ups for this app, then try again.';
    return;
  }
  status.textContent = 'Finish signing in in the pop-up window.';
  const onMessage = async (event) => {
    if (event.origin !== location.origin || event.source !== popup || event.data?.type !== 'godseye-sso') return;
    window.removeEventListener('message', onMessage);
    const response = await fetch('/api/auth/embed-session', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-GodsEye-Embed': '1' },
      body: JSON.stringify({ code: event.data.code, nonce }),
    });
    if (response.ok) location.replace(returnTo);
    else status.textContent = 'Sign-in did not complete. Try again.';
  };
  window.addEventListener('message', onMessage);
});
