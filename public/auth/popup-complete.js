// Pass the handoff code to the framed copy that opened this popup (same origin
// only), then scrub it from the address bar and close.
const code = new URLSearchParams(location.hash.slice(1)).get('code');
history.replaceState(null, '', location.pathname);
if (code && window.opener) {
  window.opener.postMessage({ type: 'godseye-sso', code }, location.origin);
  window.close();
} else {
  location.replace('/');
}
