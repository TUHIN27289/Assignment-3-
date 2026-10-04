def test_app_starts(app):
    """Test that the Flask application instance is created successfully."""
    assert app is not None
    assert app.config["TESTING"] is True

def test_health_check(client):
    """Test that GET /health returns HTTP 200 and expected status JSON."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data is not None
    assert data.get("status") == "healthy"
    assert data.get("service") == "voting-backend"
