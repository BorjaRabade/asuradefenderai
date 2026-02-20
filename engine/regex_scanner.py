import logging
from typing import List
from engine.base import BaseScanner
from core.vulnerability import Vulnerability
from rules.regex_base_rule import RegexBaseRule

class RegexScanner(BaseScanner):
    def __init__(self):
        self.rules: List[RegexBaseRule] = []

    def add_rule(self, rule: RegexBaseRule):
        self.rules.append(rule)

    def escanear(self, ruta_archivo: str) -> List[Vulnerability]:
        findings = []
        try:
            with open(ruta_archivo, "r", encoding="utf-8", errors="ignore") as f:
                for line_number, line in enumerate(f, 1):
                    for rule in self.rules:
                        finding = rule.check_line(line, line_number, ruta_archivo)
                        if finding:
                            findings.append(finding)
        except Exception as e:
            logging.error(f"Error parseando texto en {ruta_archivo}: {e}")
            
        return findings
