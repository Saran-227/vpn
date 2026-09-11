from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health():
    r = client.get('/api/health'); assert r.status_code == 200; assert r.json()['status'] == 'ok'

def test_dashboard_contract():
    data = client.get('/api/dashboard').json()
    assert {'timestamp','vpn','metrics','security','events','history','mode'} <= data.keys()
    assert 0 <= data['security']['risk_score'] <= 100

def test_metrics(): assert client.get('/api/metrics/current').status_code == 200

def test_security(): assert client.get('/api/security/current').status_code == 200
