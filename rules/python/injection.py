import ast
from rules.base_rule import BaseRule
from core.vulnerability import Vulnerability

class SQLInjectionRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.id = "SEC-SQL-INJECTION"
        self.name = "Posible Inyección SQL"
        self.severity = "HIGH"
        self.description = "Se detectó construcción dinámica de consultas SQL. Esto puede permitir inyección SQL."
        self.recommendation = "Usa consultas parametrizadas (binding parameters) en lugar de concatenación de cadenas o f-strings."

    def check(self, node: ast.AST, filename: str) -> Vulnerability:
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
                if node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.BinOp):
                         return Vulnerability(
                            id=self.id,
                            nombre=self.name,
                            severidad=self.severity,
                            archivo=filename,
                            linea=node.lineno,
                            codigo_detectado="cursor.execute(... + ...)",
                            descripcion="Concatenación directa en consulta SQL.",
                            solucion=self.recommendation
                        )
                    elif isinstance(arg, ast.JoinedStr):
                        return Vulnerability(
                            id=self.id,
                            nombre=self.name,
                            severidad=self.severity,
                            archivo=filename,
                            linea=node.lineno,
                            codigo_detectado='cursor.execute(f"...")',
                            descripcion="Uso de f-string en consulta SQL.",
                            solucion=self.recommendation
                        )
                        
        if isinstance(node, ast.Assign):
            if isinstance(node.value, (ast.BinOp, ast.JoinedStr)):
                is_sql = False
                
                for target in node.targets:
                    if isinstance(target, ast.Name) and any(x in target.id.lower() for x in ["query", "sql", "statement"]):
                        is_sql = True
                        break
                
                if not is_sql and isinstance(node.value, ast.BinOp):
                    curr = node.value
                    while isinstance(curr, ast.BinOp):
                        curr = curr.left
                    if isinstance(curr, ast.Constant) and isinstance(curr.value, str):
                        if any(curr.value.lstrip().upper().startswith(kw) for kw in ["SELECT", "INSERT", "UPDATE", "DELETE"]):
                            is_sql = True

                if not is_sql and isinstance(node.value, ast.JoinedStr):
                    if node.value.values and isinstance(node.value.values[0], ast.Constant) and isinstance(node.value.values[0].value, str):
                         val = node.value.values[0].value.strip().upper()
                         if any(val.startswith(kw) for kw in ["SELECT", "INSERT", "UPDATE", "DELETE"]):
                             is_sql = True
                
                if is_sql:
                     return Vulnerability(
                        id=self.id,
                        nombre=self.name,
                        severidad=self.severity,
                        archivo=filename,
                        linea=node.lineno,
                        codigo_detectado="query = ... + ...",
                        descripcion="Construcción dinámica de consulta SQL detectada.",
                        solucion=self.recommendation
                    )

        return None
