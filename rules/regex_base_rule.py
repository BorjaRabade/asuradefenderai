from abc import ABC, abstractmethod
from typing import Optional
from core.vulnerability import Vulnerability

class RegexBaseRule(ABC):
    def __init__(self):
        self.id = "UNKNOWN"
        self.name = "Unknown Rule"
        self.severity = "LOW"
        self.description = "No description provided"
        self.recommendation = "No recommendation provided"

    @abstractmethod
    def check_line(self, line_text: str, line_number: int, filename: str) -> Optional[Vulnerability]:
        """
        Analiza una línea de texto libre y retorna la vulnerabilidad si hay coincidencia.
        """
        pass
