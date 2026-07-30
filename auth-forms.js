// ====================================================================
// REGISTER / LOGIN / MFA-CHALLENGE FORM HANDLING
// ====================================================================

document.addEventListener('DOMContentLoaded', () => {

    // ---------------- Register ----------------
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('usernameInput').value.trim();
            const email = document.getElementById('emailInput').value.trim();
            const password = document.getElementById('passwordInput').value;
            const errorBox = document.getElementById('formError');
            errorBox.style.display = 'none';

            if (!username || !email || !password) {
                errorBox.textContent = 'Please fill out all fields.';
                errorBox.style.display = 'block';
                return;
            }

            try {
                const res = await fetch('/api/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, email, password }),
                });
                const result = await res.json();
                if (res.ok) {
                    window.location.href = 'mfa-setup.html';
                } else {
                    errorBox.textContent = result.details ? result.details.join(' ') : result.error;
                    errorBox.style.display = 'block';
                }
            } catch (err) {
                errorBox.textContent = 'Could not reach the server.';
                errorBox.style.display = 'block';
            }
        });
    }

    // ---------------- Login (step 1) ----------------
    const loginForm = document.getElementById('loginForm');
    const mfaForm = document.getElementById('mfaForm');

    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('emailInput').value.trim();
            const password = document.getElementById('passwordInput').value;
            const errorBox = document.getElementById('loginError');
            errorBox.style.display = 'none';

            try {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password }),
                });
                const result = await res.json();

                if (!res.ok) {
                    errorBox.textContent = result.error;
                    errorBox.style.display = 'block';
                    return;
                }

                if (result.mfaRequired) {
                    loginForm.style.display = 'none';
                    mfaForm.style.display = 'block';
                } else {
                    window.location.href = 'admin.html';
                }
            } catch (err) {
                errorBox.textContent = 'Could not reach the server.';
                errorBox.style.display = 'block';
            }
        });
    }

    // ---------------- Login (step 2: MFA) ----------------
    if (mfaForm) {
        mfaForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const code = document.getElementById('mfaCodeInput').value.trim();
            const errorBox = document.getElementById('mfaError');
            errorBox.style.display = 'none';

            try {
                const res = await fetch('/api/login/mfa', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code }),
                });
                const result = await res.json();

                if (res.ok) {
                    window.location.href = 'admin.html';
                } else {
                    errorBox.textContent = result.error;
                    errorBox.style.display = 'block';
                }
            } catch (err) {
                errorBox.textContent = 'Could not reach the server.';
                errorBox.style.display = 'block';
            }
        });
    }
});
