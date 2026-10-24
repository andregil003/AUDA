"""
Punto de entrada: run.py
Doble clic para lanzar la interfaz gráfica.
"""

import os
import sys

# Asegurar que se ejecute desde la carpeta del proyecto
os.chdir(os.path.dirname(os.path.abspath(__file__)))

from gui.app import AppThreatHunting
import tkinter as tk

if __name__ == "__main__":
    root = tk.Tk()
    app = AppThreatHunting(root)
    root.mainloop()
