// ─────────────────────────────────────────────────────────────────────────────
//  app.js  —  Unsecure Social PWA  —  Frontend JavaScript
//
//  INTENTIONAL VULNERABILITIES (for educational use):
//    1. DOM-based XSS       — msg parameter injected via innerHTML (no sanitisation)
//    2. Aggressive push     — requests notification permission immediately on load
//    3. Hardcoded VAPID key — visible to any student who views page source
//    4. No CSRF protection  — fetch() calls include no CSRF token
//    5. Insecure postMessage — message origin is never validated
// ─────────────────────────────────────────────────────────────────────────────

// ── Service Worker Registration ───────────────────────────────────────────────
if ('serviceWorker' in navigator) {
  window.addEventListener('load', function () {
    navigator.serviceWorker.register('/static/js/serviceWorker.js')
      .then(function (reg) {
        console.log('[App] ServiceWorker registered. Scope:', reg.scope);
        // Automatically check for SW updates on every page load
        reg.update();
      })
      .catch(function (err) {
        console.error('[App] ServiceWorker registration failed:', err);
      });
  });
}

// ── Push Notification Subscription ───────────────────────────────────────────
// VULNERABILITY: Notification permission is requested immediately on page load
// without any user-initiated action — bad practice and against browser guidelines
window.addEventListener('load', function () {
  if ('Notification' in window && 'serviceWorker' in navigator) {
    Notification.requestPermission().then(function (permission) {
      console.log('[App] Notification permission:', permission);
      if (permission === 'granted') {
        subscribeToPush();
      }
    });
  }
});

async function subscribeToPush() {
  try {
    const registration = await navigator.serviceWorker.ready;

    // VULNERABILITY: Hardcoded VAPID public key in client-side JavaScript
    // Anyone reading the source can use this key to send push messages to all subscribers
    const applicationServerKey = urlBase64ToUint8Array(
      'BEl62iUYgUivxIkv69yViEuiBIa-Ib9-SkvMeAtA3LFgDzkrxZJjSgSnfckjBJuBkr3qBUYIHBQFLXYp5Nksh8U'
    );

    const subscription = await registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: applicationServerKey
    });

    // VULNERABILITY: Push subscription POSTed to server with no CSRF token
    // An attacker who tricks the user into visiting a page can trigger this fetch
    await fetch('/subscribe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(subscription)
    });

    console.log('[App] Push subscription registered.');
  } catch (err) {
    console.warn('[App] Push subscription failed (expected if no VAPID server):', err);
  }
}

function urlBase64ToUint8Array(base64String) {
  const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
  const base64  = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  const rawData = window.atob(base64);
  const output  = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; i++) {
    output[i] = rawData.charCodeAt(i);
  }
  return output;
}

// ── DOM-based XSS (FIXED) ────────────────────────────────────────────────────────
// SECURITY FIX: Using textContent instead of innerHTML to prevent XSS
// textContent treats input as plain text, not executable HTML/JavaScript
window.addEventListener('DOMContentLoaded', function () {
  const params  = new URLSearchParams(window.location.search);
  const msg     = params.get('msg');
  const msgBox  = document.getElementById('js-msg-box');

  if (msg && msgBox) {
    // SECURE: textContent only interprets as plain text, preventing XSS
    msgBox.textContent = msg;
  }

  // ── Highlight active nav link ──────────────────────────────────────────────
  const currentPath = window.location.pathname;
  document.querySelectorAll('.nav-links a').forEach(function (link) {
    if (link.getAttribute('href') === currentPath) {
      link.style.color = '#e94560';
      link.style.fontWeight = '700';
    }
  });
});

// ── Insecure postMessage Listener (FIXED) ────────────────────────────────────────
// SECURITY FIX: Added origin validation + removed unsafe redirect/innerHTML
window.addEventListener('message', function (event) {
  // SECURE: Only accept messages from the same origin (trusted source)
  const expectedOrigin = window.location.origin;
  if (event.origin !== expectedOrigin) {
    console.warn('[App] Rejected postMessage from untrusted origin:', event.origin);
    return;  // Silently ignore messages from other domains
  }

  console.log('[App] postMessage received from trusted origin:', event.origin, 'data:', event.data);

  // REMOVED: Unsafe redirect functionality to prevent open redirect attacks
  // if (event.data && event.data.action === 'redirect') { ... }

  // ALTERNATIVE: If redirect is needed, implement URL validation
  if (event.data && event.data.action === 'redirect') {
    // Only allow internal redirects (start with /)
    if (event.data.url && event.data.url.startsWith('/')) {
      window.location.href = event.data.url;
    } else {
      console.warn('[App] Blocked redirect to external URL:', event.data.url);
    }
  }

  if (event.data && event.data.action === 'setMsg') {
    const msgBox = document.getElementById('js-msg-box');
    if (msgBox) {
      // SECURE: Use textContent instead of innerHTML to prevent XSS
      msgBox.textContent = event.data.content;
    }
  }
});

// ── PWA Install Prompt ────────────────────────────────────────────────────────
let deferredPrompt;
window.addEventListener('beforeinstallprompt', function (e) {
  e.preventDefault();
  deferredPrompt = e;

  const installBtn = document.getElementById('install-btn');
  if (installBtn) {
    installBtn.style.display = 'inline-block';
    installBtn.addEventListener('click', function () {
      deferredPrompt.prompt();
      deferredPrompt.userChoice.then(function (choiceResult) {
        console.log('[App] Install choice:', choiceResult.outcome);
        deferredPrompt = null;
        installBtn.style.display = 'none';
      });
    });
  }
});
