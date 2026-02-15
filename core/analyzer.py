import os
from typing import List
from core.vulnerability import Vulnerability
from engine.scanner import ASTScanner
from rules.python.dangerous import DangerousFunctionsRule
from rules.python.injection import SQLInjectionRule
from rules.python.secrets import HardcodedSecretRule
from rules.python.ip_exposure import IPExposureRule

class Analyzer:
    
    def __init__(self):
        self.scanner = ASTScanner()
        pass

    def cargar_reglas(self):
        self.scanner.add_rule(DangerousFunctionsRule())
        self.scanner.add_rule(SQLInjectionRule())
        self.scanner.add_rule(HardcodedSecretRule())
        self.scanner.add_rule(IPExposureRule())

    def analizar_target(self, target: str) -> List[Vulnerability]:
        vulnerabilidades = []
        
        self.cargar_reglas()
        
        if os.path.isfile(target):
            if target.endswith(".py"):
                print(f"Analizando archivo único: {target}")
                hallazgos = self.scanner.escanear(target)
                vulnerabilidades.extend(hallazgos)
        else:
            for root, dirs, files in os.walk(target):
                for file in files:
                    if file.endswith(".py"):
                        ruta_completa = os.path.join(root, file)
                        if "venv" in ruta_completa or "__pycache__" in ruta_completa:
                            continue
                            
                        print(f"Analizando: {ruta_completa}")
                        hallazgos = self.scanner.escanear(ruta_completa)
                        vulnerabilidades.extend(hallazgos)
                    
        return vulnerabilidades
