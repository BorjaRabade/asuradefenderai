import os
from core.analyzer import Analyzer

def test_generic_scan():
    print("--- TEST CLI: GENERIC SCANNING ---")
    
    analyzer = Analyzer()
    test_file = os.path.join(os.getcwd(), "test_secret.js")
    
    print(f"\nScanning Single File: {test_file}")
    vulns = analyzer.analizar_target(test_file)
    print(f"Findings: {len(vulns)}")
    
    for v in vulns:
        print(f"[{v.severidad}] {v.nombre} en {os.path.basename(v.archivo)}:{v.linea}")
        print(f"   -> Código: {v.codigo_detectado.strip()}")
        print(f"   -> Descripción: {v.descripcion}")

if __name__ == "__main__":
    test_generic_scan()
