import re
from typing import Optional
from rules.regex_base_rule import RegexBaseRule
from core.vulnerability import Vulnerability

class SecretsRegexRule(RegexBaseRule):
    def __init__(self):
        super().__init__()
        self.id = "GEN-SEC-HARDCODED-SECRET"
        self.name = "Secreto Hardcodeado (Genérico)"
        self.severity = "CRITICAL"
        self.description = "Se detectó una posible credencial o clave genérica expuesta en texto plano."
        self.recommendation = "Mueve las credenciales a variables de entorno o un gestor de secretos seguro."
        
        # Regex elements to search for plain credentials/keys
        self.patterns = [
            r"AKIA[0-9A-Z]{16}",
            r"(?i)(?:api[_-]?key|secret|password|token)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{8,}['\"]?"
        ]

    def check_line(self, line_text: str, line_number: int, filename: str) -> Optional[Vulnerability]:
        for pattern in self.patterns:
            match = re.search(pattern, line_text)
            if match:
                detected = match.group()
                return Vulnerability(
                    id=self.id,
                    nombre=self.name,
                    severidad=self.severity,
                    archivo=filename,
                    linea=line_number,
                    codigo_detectado=line_text.strip(),
                    descripcion=self.description,
                    solucion=self.recommendation
                )
        return None
