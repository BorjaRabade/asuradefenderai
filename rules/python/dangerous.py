import ast
from rules.base_rule import BaseRule
from core.vulnerability import Vulnerability

class DangerousFunctionsRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.id = "SEC-DANGEROUS-FUNC"
        self.name = "Uso de Funciones Peligrosas"
        self.severity = "CRITICAL"
        self.description = "Se detectó el uso de una función potencialmente peligrosa que permite ejecución de código arbitrario."
        self.recommendation = "Evita usar eval(), exec() o pickle. La entrada no confiable en estas funciones puede llevar a compromiso total del sistema."
        self.blocklist = {"eval", "exec"}

    def check(self, node: ast.AST, filename: str) -> Vulnerability:
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id in self.blocklist:
                    return Vulnerability(
                        id=self.id,
                        nombre=self.name,
                        severidad=self.severity,
                        archivo=filename,
                        linea=node.lineno,
                        codigo_detectado=f"{node.func.id}(...)",
                        descripcion=f"Uso de función peligrosa: {node.func.id}",
                        solucion=self.recommendation
                    )
        return None
