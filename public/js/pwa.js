// Talk-Secure — PWA Service Worker Registration
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js')
            .then((reg) => console.log('📦 Service Worker registered:', reg.scope))
            .catch((err) => console.warn('SW registration failed:', err));
    });
}
