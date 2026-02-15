import os
import pickle

def run_code(user_input):
    # Vulnerabilidad: Uso de eval()
    result = eval(user_input)
    return result

def exec_code(script):
    # Vulnerabilidad: Uso de exec()
    exec(script)

def deserialize(data):
    # Vulnerabilidad: Uso de pickle.loads con datos no confiables (implícito en la regla de dangerous functions si estuviera, pero eval/exec son las principales aquí)
    return pickle.loads(data)
