// ====================================================================
// ADMIN PROMOTION SCRIPT — run manually from the command line only.
//
// Deliberately NOT exposed as an HTTP route: allowing a logged-in
// user to grant themselves admin rights via an API call would be a
// Broken Access Control vulnerability (OWASP A01:2021 — privilege
// escalation). Promoting an account to admin is treated as a
// server-operator action, not an application feature.
//
// Usage:
//   1. Register a normal account first at /register.html
//   2. Then run:  node seed-admin.js you@example.com
// ====================================================================

const q = require('./db/queries.js');

const email = process.argv[2];

if (!email) {
    console.error('Usage: node seed-admin.js <email>');
    process.exit(1);
}

const promoted = q.promoteToAdmin(email.trim().toLowerCase());

if (promoted) {
    console.log(`✔ ${email} is now an admin. Log in again to refresh the session.`);
} else {
    console.error(`✘ No user found with email "${email}". Register that account first.`);
}
