import os
from typing import List
from core.vulnerability import Vulnerability
from engine.scanner import ASTScanner
from engine.regex_scanner import RegexScanner

from rules.python.dangerous import DangerousFunctionsRule
from rules.python.injection import SQLInjectionRule
from rules.python.secrets import HardcodedSecretRule
from rules.python.ip_exposure import IPExposureRule

from rules.generic.secrets_regex import SecretsRegexRule
from rules.generic.ip_regex import IPExposureRegexRule

class Analyzer:
    
    def __init__(self):
        self.ast_scanner = ASTScanner()
        self.regex_scanner = RegexScanner()

    def cargar_reglas(self):
        # Reglas Python Específicas
        self.ast_scanner.add_rule(DangerousFunctionsRule())
        self.ast_scanner.add_rule(SQLInjectionRule())
        self.ast_scanner.add_rule(HardcodedSecretRule())
        self.ast_scanner.add_rule(IPExposureRule())
        
        # Reglas Genéricas Textuales
        self.regex_scanner.add_rule(SecretsRegexRule())
        self.regex_scanner.add_rule(IPExposureRegexRule())

    def _es_texto(self, ruta_archivo: str) -> bool:
        # Chequeo simple de archivo binario o texto
        try:
            with open(ruta_archivo, 'tr', encoding='utf-8') as check_file:
                check_file.read(1024)
                return True
        except UnicodeDecodeError:
            return False
        except Exception:
            return False

    def analizar_target(self, target: str) -> List[Vulnerability]:
        vulnerabilidades = []
        
        self.cargar_reglas()
        
        if os.path.isfile(target):
            print(f"Analizando archivo: {target}")
            if self._es_texto(target):
                vulnerabilidades.extend(self.regex_scanner.escanear(target))
                if target.endswith(".py"):
                    vulnerabilidades.extend(self.ast_scanner.escanear(target))
        else:
            for root, dirs, files in os.walk(target):
                for file in files:
                    ruta_completa = os.path.join(root, file)
                    if "venv" in ruta_completa or "__pycache__" in ruta_completa or ".git" in ruta_completa:
                        continue
                        
                    print(f"Analizando: {ruta_completa}")
                    if self._es_texto(ruta_completa):
                        hallazgos = self.regex_scanner.escanear(ruta_completa)
                        vulnerabilidades.extend(hallazgos)
                        
                        if ruta_completa.endswith(".py"):
                            hallazgos_py = self.ast_scanner.escanear(ruta_completa)
                            vulnerabilidades.extend(hallazgos_py)
                    
        return vulnerabilidades
