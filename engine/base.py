from abc import ABC, abstractmethod
from typing import List
from core.vulnerability import Vulnerability

class BaseScanner(ABC):
    @abstractmethod
    def escanear(self, ruta_archivo: str) -> List[Vulnerability]:
        pass
