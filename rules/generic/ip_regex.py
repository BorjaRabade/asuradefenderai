import re
from typing import Optional
from rules.regex_base_rule import RegexBaseRule
from core.vulnerability import Vulnerability

class IPExposureRegexRule(RegexBaseRule):
    def __init__(self):
        super().__init__()
        self.id = "GEN-SEC-IP-EXPOSURE"
        self.name = "Exposición de Dirección IP (Genérica)"
        self.severity = "MEDIUM"
        self.description = "Se detectó una dirección IP IPv4 hardcodeada."
        self.recommendation = "Utiliza nombres de host (DNS) o carga IPs desde la configuración."
        
        self.ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'

    def check_line(self, line_text: str, line_number: int, filename: str) -> Optional[Vulnerability]:
        matches = re.finditer(self.ip_pattern, line_text)
        for match in matches:
            ip = match.group()
            
            # Reduce severity for localhost
            current_severity = self.severity
            desc = self.description
            if ip.startswith("127.") or ip == "0.0.0.0":
                current_severity = "LOW"
                desc = "Dirección IP local hardcodeada (Loopback/Any)."

            return Vulnerability(
                id=self.id,
                nombre=self.name,
                severidad=current_severity,
                archivo=filename,
                linea=line_number,
                codigo_detectado=line_text.strip()[:100], # Limit length
                descripcion=desc,
                solucion=self.recommendation
            )
        return None
