import sqlite3

def get_user_unsafe(username):
    # Vulnerabilidad: Concatenación directa de strings
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    
    # Vulnerabilidad: Ejecución de query concatenada
    cursor.execute(query) 
    
    # Vulnerabilidad: Uso de f-strings en query
    cursor.execute(f"SELECT * FROM products WHERE name = '{username}'")
    
    return cursor.fetchall()
