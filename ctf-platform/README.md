# Hackstreetboys CTF Learning Platform

An educational Capture-the-Flag web application built for CSCE 4907 Cybersecurity Capstone.

## Setup

Requires Python 3.10+.

```bash
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
python app.py
```

Visit http://127.0.0.1:5000 and register a student account.

## Running tests

```bash
pytest -q
```

## Admin access (local development)

After registering a user, stop the server and run this from the project directory:

```bash
python -c "from app import app, db, User; ctx=app.app_context(); ctx.push(); u=User.query.filter_by(username='YOUR_USERNAME').first(); assert u is not None; u.is_admin=True; db.session.commit(); ctx.pop()"
```

Replace `YOUR_USERNAME` with the account you registered. Restart the server and log in to see the Admin link. Do not run this for untrusted accounts.

## Security and limitations

Passwords use Werkzeug's secure password hashing. Flag answers are stored as SHA-256 digests, and the app uses session cookies, CSRF tokens, server-side access control, and basic security headers. The app is for **local classroom demonstration**; do not expose it publicly without additional hardening. Add login/flag rate limiting, a persistent strong SECRET_KEY, HTTPS, migrations, secure cookie settings, and scalable flag handling before production. For a real CTF, use keyed flag digests or per-user flags because short known-format flags can be guessed offline if the database leaks. The random fallback SECRET_KEY changes on restart, so existing sessions will be invalidated. The SQLite database is created under Flask's `instance/` directory. Never commit it or your secret key.

## Demo flow

1. Register a student and log in.
2. Solve Welcome Flag using the example provided in the challenge.
3. View updated points and leaderboard.
4. Enable admin privileges locally using the command above.
5. Create a new challenge from the admin panel.

## Next sprints

Add hints, challenge attachments, challenge categories and difficulty levels, per-user flags, rate limiting, audit logs, deployment, and improved test coverage.
