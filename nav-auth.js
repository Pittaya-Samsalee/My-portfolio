// ====================================================================
// SHARED NAV AUTH STATE
// Checks the current session (via HttpOnly cookie, sent automatically
// by the browser) and updates the navbar accordingly on every page.
// ====================================================================

document.addEventListener('DOMContentLoaded', async () => {
    const navLink = document.getElementById('navAuthLink');
    if (!navLink) return;

    try {
        const res = await fetch('/api/me');
        if (res.ok) {
            const user = await res.json();
            navLink.textContent = user.role === 'admin' ? 'ADMIN' : 'ACCOUNT';
            navLink.href = user.role === 'admin' ? 'admin.html' : 'mfa-setup.html';
        }
        // If not logged in (401), leave the default "LOGIN" link as-is.
    } catch (err) {
        // Network/server not reachable — leave default link, fail silently.
    }
});
