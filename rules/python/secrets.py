import ast
import re
from rules.base_rule import BaseRule
from core.vulnerability import Vulnerability

class HardcodedSecretRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.id = "SEC-HARDCODED-SECRET"
        self.name = "Secreto Hardcodeado"
        self.severity = "CRITICAL"
        self.description = "Se detectó una posible credencial o clave secreta en el código."
        self.recommendation = "Mueve las credenciales a variables de entorno o un gestor de secretos. No las guardes en el repositorio."
        
        self.secret_patterns = [
            r"AKIA[0-9A-Z]{16}",
            r"(?i)(api_key|secret|password|token)\s*=\s*['\"][a-zA-Z0-9_\-]{8,}['\"]"
        ]

    def check(self, node: ast.AST, filename: str) -> Vulnerability:
        if isinstance(node, ast.Assign):
            if isinstance(node.value, (ast.Constant, ast.Str)):
                valor = node.value.value if isinstance(node.value, ast.Constant) else node.value.s
                
                if not isinstance(valor, str):
                    return None
                    
                if re.search(r"AKIA[0-9A-Z]{16}", valor):
                     return Vulnerability(
                        id=self.id,
                        nombre="Clave AWS Hardcodeada",
                        severidad="CRITICAL",
                        archivo=filename,
                        linea=node.lineno,
                        codigo_detectado="AKIA...",
                        descripcion="Se encontró un ID de clave de acceso de AWS.",
                        solucion=self.recommendation
                    )

                for target in node.targets:
                    if isinstance(target, ast.Name):
                        nombre_var = target.id.lower()
                        if any(s in nombre_var for s in ['secret', 'password', 'api_key', 'token']):
                            if len(valor) > 8 and " " not in valor:
                                return Vulnerability(
                                    id=self.id,
                                    nombre="Posible Credencial en Variable",
                                    severidad="HIGH",
                                    archivo=filename,
                                    linea=node.lineno,
                                    codigo_detectado=f"{target.id} = ...",
                                    descripcion=f"La variable '{target.id}' parece contener un secreto.",
                                    solucion=self.recommendation
                                )
        return None
