import sys
import subprocess
import os

def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

def check_dependencies():
    print("Verificando dependencias...")
    try:
        import customtkinter
        import groq
        import dotenv
        import packaging
        print("Dependencias encontradas.")
    except ImportError:
        print("Faltan dependencias. Instalando...")
        try:
            requirements_path = os.path.join(os.path.dirname(__file__), "requirements.txt")
            if os.path.exists(requirements_path):
                subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", requirements_path])
                print("Dependencias instaladas correctamente.")
            else:
                print("No se encontró requirements.txt. Intentando instalar paquetes manualmente...")
                install("customtkinter")
                install("groq")
                install("python-dotenv")
                install("packaging")
        except Exception as e:
            print(f"Error instalando dependencias: {e}")
            input("Presione Enter para salir...")
            sys.exit(1)

if __name__ == "__main__":
    check_dependencies()
    
    # Iniciar la aplicación principal
    try:
        from main import App
        app = App()
        app.mainloop()
    except Exception as e:
        print(f"Error iniciando la aplicación: {e}")
        import traceback
        traceback.print_exc()
        input("Presione Enter para salir...")
