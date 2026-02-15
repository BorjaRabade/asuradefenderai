import os

def connect_to_aws():
    # Vulnerabilidad: AWS Access Key ID hardcodeada
    ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE" 
    SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    
    print(f"Connecting with {ACCESS_KEY}...")

def db_config():
    # Vulnerabilidad: Contraseña en variable
    db_password = "super_secret_password_123"
    api_token = "abcdef1234567890abcdef1234567890" # Token largo
    
    return db_password
