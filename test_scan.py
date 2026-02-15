import os
from core.analyzer import Analyzer

def main():
    print("--- TEST CLI: AUDITOR AUTOMATIZADO ---")
    
    # Ruta actual
    target = os.getcwd()
    print(f"Target: {target}")
    
    analyzer = Analyzer()
    
    # Test 1: Scan vulnerable.py (Directory Scan context)
    print(f"\nScanning Directory: {target}")
    vulnerabilities = analyzer.analizar_target(target)
    print(f"Directory Scan Found: {len(vulnerabilities)}")

    # Test 2: Scan test_input.py (Single File Scan context)
    test_file = os.path.join(target, "test_input.py")
    if os.path.exists(test_file):
        print(f"\nScanning Single File: {test_file}")
        single_vulns = analyzer.analizar_target(test_file)
        print(f"Single File Scan Found: {len(single_vulns)}")
        for v in single_vulns:
            print(f"[{v.severidad}] {v.nombre}: {v.codigo_detectado}")
            if "input" in v.codigo_detectado and "eval" not in v.codigo_detectado:
                print("!! FAILURE: input() was flagged !!")
            else:
                print(">> Success: Detection looks correct")


if __name__ == "__main__":
    main()
