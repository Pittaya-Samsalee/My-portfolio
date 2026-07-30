// ====================================================================
// MFA SETUP PAGE LOGIC
// ====================================================================

document.addEventListener('DOMContentLoaded', async () => {
    const statusEl = document.getElementById('mfaStatus');
    const setupBlock = document.getElementById('setupBlock');
    const enabledBlock = document.getElementById('enabledBlock');
    const startSetupBtn = document.getElementById('startSetupBtn');
    const confirmMfaBtn = document.getElementById('confirmMfaBtn');
    const disableMfaBtn = document.getElementById('disableMfaBtn');
    const logoutLink = document.getElementById('logoutLink');

    async function loadStatus() {
        const res = await fetch('/api/me');
        if (!res.ok) {
            window.location.href = 'login.html';
            return;
        }
        const user = await res.json();
        if (user.mfaEnabled) {
            statusEl.textContent = `Signed in as ${user.username}.`;
            enabledBlock.style.display = 'block';
            setupBlock.style.display = 'none';
            startSetupBtn.style.display = 'none';
        } else {
            statusEl.textContent = `Signed in as ${user.username}. MFA is not yet enabled.`;
            enabledBlock.style.display = 'none';
            startSetupBtn.style.display = 'block';
        }
    }

    startSetupBtn.addEventListener('click', async () => {
        const res = await fetch('/api/mfa/setup', { method: 'POST' });
        const data = await res.json();
        document.getElementById('secretText').textContent = data.secret;
        document.getElementById('qrcode').innerHTML = '';
        // eslint-disable-next-line no-undef
        new QRCode(document.getElementById('qrcode'), {
            text: data.otpauthUri,
            width: 200,
            height: 200,
        });
        startSetupBtn.style.display = 'none';
        setupBlock.style.display = 'block';
    });

    confirmMfaBtn.addEventListener('click', async () => {
        const code = document.getElementById('confirmCodeInput').value.trim();
        const errorBox = document.getElementById('setupError');
        errorBox.style.display = 'none';
        const res = await fetch('/api/mfa/enable', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code }),
        });
        const data = await res.json();
        if (res.ok) {
            await loadStatus();
        } else {
            errorBox.textContent = data.error;
            errorBox.style.display = 'block';
        }
    });

    if (disableMfaBtn) {
        disableMfaBtn.addEventListener('click', async () => {
            await fetch('/api/mfa/disable', { method: 'POST' });
            await loadStatus();
        });
    }

    logoutLink.addEventListener('click', async (e) => {
        e.preventDefault();
        await fetch('/api/logout', { method: 'POST' });
        window.location.href = 'login.html';
    });

    await loadStatus();
});
