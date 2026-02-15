import ast
import re
from core.vulnerability import Vulnerability
from rules.base_rule import BaseRule

class IPExposureRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.id = "SEC-IP-EXPOSURE"
        self.name = "Exposición de Dirección IP"
        self.severity = "MEDIUM"
        self.description = "Se detectó una dirección IP IPv4 hardcodeada. Esto puede exponer infraestructura interna o endpoints sensibles."
        self.recommendation = "Utiliza nombres de host (DNS) o carga las IPs desde variables de configuración/entorno."
        
        # Regex para IPv4 (0-255.0-255.0-255.0-255)
        self.ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'

    def check(self, node: ast.AST, filename: str) -> Vulnerability:
        # Buscamos en strings constantes
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            matches = re.finditer(self.ip_pattern, node.value)
            for match in matches:
                ip = match.group()
                
                # Excluir localhost y 0.0.0.0 de alertas ruidosas si se desea
                # Por ahora los marcamos como 'LOW' o 'INFO' si son locales, pero el requerimiento es rastrear IPs.
                # Vamos a reportar todo pero ajustar severidad si es local.
                
                current_severity = self.severity
                if ip.startswith("127.") or ip == "0.0.0.0":
                    current_severity = "LOW"
                    desc = "Dirección IP local hardcodeada (Loopback/Any)."
                else:
                    desc = self.description

                return Vulnerability(
                    id=self.id,
                    nombre=self.name,
                    severidad=current_severity,
                    archivo=filename,
                    linea=node.lineno,
                    codigo_detectado=f"IP encontrada: {ip}",
                    descripcion=desc,
                    solucion=self.recommendation
                )
        return None
