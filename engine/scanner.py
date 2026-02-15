import ast
import logging
from typing import List, Type
from engine.base import BaseScanner
from core.vulnerability import Vulnerability
from rules.base_rule import BaseRule

class ASTScanner(BaseScanner):
    def __init__(self):
        self.rules: List[BaseRule] = []

    def add_rule(self, rule: BaseRule):
        self.rules.append(rule)

    def escanear(self, ruta_archivo: str) -> List[Vulnerability]:
        findings = []
        try:
            with open(ruta_archivo, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            tree = ast.parse(content, filename=ruta_archivo)
            
            for node in ast.walk(tree):
                for rule in self.rules:
                    finding = rule.check(node, ruta_archivo)
                    if finding:
                        if hasattr(node, 'lineno'):
                            lines = content.splitlines()
                            start = max(0, node.lineno - 1)
                            end = node.end_lineno if hasattr(node, 'end_lineno') else start + 1
                            finding.codigo_detectado = "\n".join(lines[start:end]).strip()
                        
                        findings.append(finding)
                        
        except SyntaxError:
            logging.error(f"Error de sintaxis parseando {ruta_archivo}")
        except Exception as e:
            logging.error(f"Error escaneando {ruta_archivo}: {e}")
            
        return findings
