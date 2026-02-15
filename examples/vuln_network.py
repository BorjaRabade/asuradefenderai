import requests

def connect_internal():
    # Vulnerabilidad: IP Privada hardcodeada
    internal_server = "192.168.1.100"
    response = requests.get(f"http://{internal_server}/api/status")
    return response.json()

def connect_db_direct():
    # Vulnerabilidad: IP Pública hardcodeada
    db_host = "203.0.113.45"
    print(f"Connecting to database at {db_host}")
