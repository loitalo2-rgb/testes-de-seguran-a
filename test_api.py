import pytest
import requests

# Fixture para a URL base da API
@pytest.fixture
def api_url():
    return "https://jsonplaceholder.typicode.com/posts/1"

def test_api_status_and_payload(api_url):
    response = requests.get(api_url, timeout=10)

    assert response.status_code == 200, f"Esperado 200, recebido {response.status_code}"
    data = response.json()
    assert "userId" in data
    assert data["id"] == 1
