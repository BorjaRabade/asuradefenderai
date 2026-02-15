from abc import ABC, abstractmethod
import ast
from typing import Optional, Any
from core.vulnerability import Vulnerability

class BaseRule(ABC):
    def __init__(self):
        self.id = "UNKNOWN"
        self.name = "Unknown Rule"
        self.severity = "LOW"
        self.description = "No description provided"
        self.recommendation = "No recommendation provided"

    @abstractmethod
    def check(self, node: ast.AST, filename: str) -> Optional[Vulnerability]:
        #Analiza nodo AST y retorna la vulnerabilidad si hay
        pass
