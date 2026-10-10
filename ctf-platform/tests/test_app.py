import pytest
from app import create_app, db, User

@pytest.fixture
def client(tmp_path):
    app = create_app({'TESTING': True, 'SQLALCHEMY_DATABASE_URI': 'sqlite:///' + str(tmp_path / 'test.db'), 'SECRET_KEY': 'test-secret'})
    with app.test_client() as client:
        yield client

def token(client):
    with client.session_transaction() as sess:
        if 'csrf_token' not in sess:
            sess['csrf_token'] = 'test-csrf'
        return sess['csrf_token']

def register(client, name='student', password='correcthorsebattery'):
    return client.post('/register', data={'username': name, 'password': password, 'csrf_token': token(client)}, follow_redirects=True)

def login(client, name='student', password='correcthorsebattery'):
    return client.post('/login', data={'username': name, 'password': password, 'csrf_token': token(client)}, follow_redirects=True)

def test_registration_and_login(client):
    assert b'Account created' in register(client).data
    assert b'Welcome, student' in login(client).data

def test_unauthenticated_dashboard_redirects(client):
    assert client.get('/dashboard').status_code == 302

def test_csrf_required(client):
    assert client.post('/register', data={'username': 'student', 'password': 'correcthorsebattery'}).status_code == 400

def test_invalid_password(client):
    register(client)
    assert b'Invalid username or password' in login(client, password='wrong').data

def test_flag_submission_and_no_duplicate_points(client):
    register(client)
    login(client)
    payload = {'csrf_token': token(client), 'flag': 'CTF{welcome_to_hackstreetboys}'}
    assert b'Correct! +50 points' in client.post('/challenge/1/submit', data=payload, follow_redirects=True).data
    assert b'already solved' in client.post('/challenge/1/submit', data=payload, follow_redirects=True).data
    assert b'50' in client.get('/leaderboard').data

def test_wrong_flag(client):
    register(client)
    login(client)
    assert b'Incorrect flag' in client.post('/challenge/1/submit', data={'csrf_token': token(client), 'flag': 'CTF{wrong}'}, follow_redirects=True).data

def test_admin_forbidden(client):
    register(client)
    login(client)
    assert client.get('/admin/challenges').status_code == 403

def test_admin_can_create_challenge(client):
    register(client)
    with client.application.app_context():
        user = User.query.filter_by(username='student').first()
        user.is_admin = True
        db.session.commit()
    login(client)
    response = client.post('/admin/challenges', data={'csrf_token': token(client), 'title': 'New Challenge', 'category': 'Basics', 'description': 'Try a flag', 'points': '75', 'flag': 'CTF{new}'}, follow_redirects=True)
    assert b'Challenge created' in response.data
