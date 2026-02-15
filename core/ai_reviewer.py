import os
import logging
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

class AIReviewer:
    def __init__(self):
        self.api_key = os.getenv("GROQ_API_KEY")
        if not self.api_key:
            logging.warning("GROQ_API_KEY no encontrada en .env")
            self.client = None
        else:
            try:
                self.client = Groq(api_key=self.api_key)
            except Exception as e:
                logging.error(f"Error inicializando Groq: {e}")
                self.client = None

    def analizar_vulnerabilidad(self, vul_nombre: str, codigo: str) -> str:
        """
        Envía el código a la IA para un análisis de segunda opinión.
        """
        if not self.client:
            return "Error: API Key de Groq no configurada."

        prompt = f"""
        Actúa como un Auditor de Seguridad Senior. Revisa el siguiente código que ha sido marcado como una vulnerabilidad de tipo "{vul_nombre}".

        CÓDIGO:
        ```python
        {codigo}
        ```

        TU TAREA:
        1. Determina si es un Verdadero Positivo o un Falso Positivo.
        2. Explica brevemente el riesgo real.
        3. Si es vulnerable, da una solución segura en una línea.
        
        Responde en formato muy conciso (máximo 3 líneas).
        """

        try:
            chat_completion = self.client.chat.completions.create(
                messages=[
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
                model="llama-3.3-70b-versatile", # Modelo más robusto y actualizado
                temperature=0.1, # Determinista
                max_tokens=150,
            )
            return chat_completion.choices[0].message.content
        except Exception as e:
            return f"Error en análisis IA: {str(e)}"
