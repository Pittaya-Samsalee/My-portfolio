// ====================================================================
// ADMIN DASHBOARD LOGIC — SELECT / UPDATE / DELETE on contact messages
// (INSERT happens via the public contact form, contact.html)
//
// Note: user-supplied text is inserted via textContent (never
// innerHTML) so that even already-sanitised data cannot be
// re-interpreted as HTML in the browser — defence in depth against XSS.
// ====================================================================

let currentEditingId = null;

document.addEventListener('DOMContentLoaded', async () => {
    const gateEl = document.getElementById('adminGate');
    const contentEl = document.getElementById('dashboardContent');
    const tbody = document.getElementById('messagesTableBody');
    const editPanel = document.getElementById('editPanel');
    const logoutLink = document.getElementById('logoutLink');

    async function checkAdminAccess() {
        const res = await fetch('/api/me');
        if (!res.ok) {
            window.location.href = 'login.html';
            return false;
        }
        const user = await res.json();
        if (user.role !== 'admin') {
            gateEl.textContent = 'This dashboard is restricted to admin accounts. Your account does not have admin privileges.';
            return false;
        }
        return true;
    }

    // ---------------- SELECT (list all messages) ----------------
    async function loadMessages() {
        const res = await fetch('/api/messages');
        if (!res.ok) {
            gateEl.textContent = 'Could not load messages (are you an admin?).';
            return;
        }
        const messages = await res.json();
        contentEl.style.display = 'block';
        tbody.innerHTML = '';

        messages.forEach((msg) => {
            const tr = document.createElement('tr');

            const idTd = document.createElement('td');
            idTd.textContent = msg.id;

            const nameTd = document.createElement('td');
            nameTd.textContent = msg.sender_name;

            const emailTd = document.createElement('td');
            emailTd.textContent = msg.sender_email;

            const msgTd = document.createElement('td');
            msgTd.className = 'msg-cell';
            msgTd.textContent = msg.message_text;

            const dateTd = document.createElement('td');
            dateTd.textContent = msg.submitted_at;

            const actionsTd = document.createElement('td');
            const editBtn = document.createElement('button');
            editBtn.textContent = 'Edit';
            editBtn.className = 'btn btn-primary btn-sm';
            editBtn.addEventListener('click', () => openEditPanel(msg));

            const delBtn = document.createElement('button');
            delBtn.textContent = 'Delete';
            delBtn.className = 'btn btn-danger btn-sm';
            delBtn.addEventListener('click', () => deleteMessage(msg.id));

            actionsTd.append(editBtn, delBtn);
            tr.append(idTd, nameTd, emailTd, msgTd, dateTd, actionsTd);
            tbody.appendChild(tr);
        });
    }

    // ---------------- UPDATE ----------------
    function openEditPanel(msg) {
        currentEditingId = msg.id;
        document.getElementById('editName').value = msg.sender_name;
        document.getElementById('editEmail').value = msg.sender_email;
        document.getElementById('editMessage').value = msg.message_text;
        document.getElementById('editError').style.display = 'none';
        editPanel.style.display = 'flex';
    }

    document.getElementById('cancelEditBtn').addEventListener('click', () => {
        editPanel.style.display = 'none';
        currentEditingId = null;
    });

    document.getElementById('saveEditBtn').addEventListener('click', async () => {
        const senderName = document.getElementById('editName').value.trim();
        const senderEmail = document.getElementById('editEmail').value.trim();
        const messageText = document.getElementById('editMessage').value.trim();
        const errorBox = document.getElementById('editError');

        const res = await fetch(`/api/messages/${currentEditingId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ senderName, senderEmail, messageText }),
        });
        const data = await res.json();

        if (res.ok) {
            editPanel.style.display = 'none';
            currentEditingId = null;
            await loadMessages();
        } else {
            errorBox.textContent = data.error;
            errorBox.style.display = 'block';
        }
    });

    // ---------------- DELETE ----------------
    async function deleteMessage(id) {
        if (!confirm(`Delete message #${id}? This cannot be undone.`)) return;
        const res = await fetch(`/api/messages/${id}`, { method: 'DELETE' });
        if (res.ok) {
            await loadMessages();
        } else {
            alert('Failed to delete message.');
        }
    }

    // ---------------- Logout ----------------
    logoutLink.addEventListener('click', async (e) => {
        e.preventDefault();
        await fetch('/api/logout', { method: 'POST' });
        window.location.href = 'login.html';
    });

    // ---------------- Init ----------------
    const isAdmin = await checkAdminAccess();
    if (isAdmin) {
        await loadMessages();
    }
});
