import pytest
import requests

# 1. TESTE DE API REST (Consumo HTTP / JSON)
def test_api_status_and_payload():
    url = "https://jsonplaceholder.typicode.com/posts/1"
    response = requests.get(url, timeout=10)
    
    assert response.status_code == 200, f"Esperado 200, recebido {response.status_code}"
    data = response.json()
    assert "userId" in data
    assert data["id"] == 1

# 2. TESTE DE RESILIÊNCIA & TRATAMENTO DE ERRO
def test_exception_handling():
    def process_data(value):
        if not isinstance(value, dict):
            raise ValueError("Payload inválido")
        return value.get("status")

    with pytest.raises(ValueError) as exc_info:
        process_data("string_invalida")
    
    assert "Payload inválido" in str(exc_info.value)
