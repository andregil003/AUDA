"""
Punto de entrada: run.py
Doble clic para lanzar la interfaz gráfica.
"""

import os
import sys

# Asegurar que se ejecute desde la carpeta del proyecto
os.chdir(os.path.dirname(os.path.abspath(__file__)))

try:
    from gui.app import AppThreatHunting
    import tkinter as tk

    if __name__ == "__main__":
        root = tk.Tk()
        app = AppThreatHunting(root)
        root.mainloop()
except Exception as e:
    import traceback
    traceback.print_exc()
    print("\n" + "=" * 60)
    print("ERROR AL INICIAR LA APLICACIÓN")
    print("=" * 60)
    print(str(e))
    print("\nPosibles soluciones:")
    print("1. Asegúrate de tener Python 3 instalado")
    print("2. Ejecuta desde la carpeta del proyecto: python3 run.py")
    print("3. En Windows, si tkinter falta, reinstala Python marcando 'tcl/tk'")
    input("\nPresiona Enter para salir...")
