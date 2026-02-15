import os
import shutil
import subprocess
import sys
import time
from datetime import datetime

# Configuracion
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DIST_DIR = os.path.join(PROJECT_ROOT, "dist")
EXE_NAME = "AsuraDefenderAI.exe"
EXE_PATH = os.path.join(DIST_DIR, EXE_NAME)
BACKUPS_DIR = os.path.join(PROJECT_ROOT, "backups")
SPEC_FILE = os.path.join(PROJECT_ROOT, "AsuraDefenderAI.spec")

def backup_existing_build():
    """Mueve el ejecutable existente a una carpeta de backup con timestamp."""
    if os.path.exists(EXE_PATH):
        print(f"[INFO] Backup: Se encontró una build existente en {EXE_PATH}")
        
        # Crear directorio de backups si no existe
        if not os.path.exists(BACKUPS_DIR):
            os.makedirs(BACKUPS_DIR)
            print(f"[INFO] Backup: Directorio {BACKUPS_DIR} creado.")
            
        # Crear carpeta con timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_folder_name = f"build_{timestamp}"
        backup_path = os.path.join(BACKUPS_DIR, backup_folder_name)
        
        os.makedirs(backup_path)
        
        # Mover el archivo
        shutil.move(EXE_PATH, os.path.join(backup_path, EXE_NAME))
        print(f"[EXITO] Backup completado: {EXE_NAME} movido a {backup_path}")
    else:
        print("[INFO] No se encontró build previa para respaldar.")

def run_build():
    """Ejecuta PyInstaller para crear una nueva build."""
    print(f"[INFO] Iniciando proceso de build con PyInstaller...")
    
    # Comando de build
    # Usamos sys.executable para asegurar que usamos el mismo interprete de python
    cmd = [
        sys.executable, "-m", "PyInstaller",
        SPEC_FILE,
        "--clean",
        "--noconfirm"
    ]
    
    try:
        # Ejecutar y esperar
        process = subprocess.run(cmd, cwd=PROJECT_ROOT)
        
        if process.returncode == 0:
            print("\n" + "="*50)
            print(f"[EXITO] Build finalizada correctamente.")
            print(f"Nueva build disponible en: {EXE_PATH}")
            print("="*50)
        else:
            print("\n" + "="*50)
            print(f"[ERROR] La build falló con código de salida {process.returncode}.")
            print("="*50)
            sys.exit(process.returncode)
            
    except Exception as e:
        print(f"[ERROR] Ocurrió una excepción al ejecutar la build: {e}")
        sys.exit(1)

if __name__ == "__main__":
    print(f"--- AsuraDefenderAI Build Manager ---")
    print(f"Fecha: {datetime.now()}")
    
    backup_existing_build()
    run_build()
    
    print("\nProceso finalizado.")
    time.sleep(2) # Pausa para que el usuario pueda ver el resultado si lo ejecuta con doble click
