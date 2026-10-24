"""
Módulo: gui/app.py
Responsable: andreGil (integración)
Función: Interfaz gráfica simple, tema negro, sin terminal.
Requisitos: Python (Tkinter viene incluido).
"""

import tkinter as tk
from tkinter import messagebox
import webbrowser
import os
import sys
import json
from datetime import datetime

# Agregar src al path para importar módulos
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from extractor import extraer_iocs
from correlator import detectar_gaps
from report_generator import generar_reporte
from historial_manager import listar_escaneos

# Rutas absolutas basadas en la ubicación de este archivo
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
DATA_FEEDS = os.path.join(PROJECT_DIR, "data", "feeds_simulados.json")
DATA_INVENTARIO = os.path.join(PROJECT_DIR, "data", "inventario_empresa.json")
HISTORIAL_DIR = os.path.join(PROJECT_DIR, "historial")


class AppThreatHunting:
    def __init__(self, root):
        self.root = root
        self.root.title("Threat Hunting - Detección de Gaps")
        self.root.geometry("800x500")
        self.root.configure(bg="#1a1a1a")

        # Evitar que la ventana se cierre sola si hay error crítico
        self.root.protocol("WM_DELETE_WINDOW", self.root.quit)

        self._construir_interfaz()
        self._cargar_historial()

    def _construir_interfaz(self):
        # Título
        lbl_titulo = tk.Label(
            self.root,
            text="Threat Hunting - Detección de Gaps",
            bg="#1a1a1a",
            fg="#00ff88",
            font=("Segoe UI", 16, "bold"),
        )
        lbl_titulo.pack(pady=15)

        # Botón escanear
        btn_escanear = tk.Button(
            self.root,
            text="Escanear ahora",
            bg="#00ff88",
            fg="#000000",
            font=("Segoe UI", 12, "bold"),
            width=20,
            command=self._ejecutar_escaneo,
        )
        btn_escanear.pack(pady=10)

        # Etiqueta historial
        lbl_historial = tk.Label(
            self.root,
            text="Historial de escaneos:",
            bg="#1a1a1a",
            fg="#cccccc",
            font=("Segoe UI", 11),
        )
        lbl_historial.pack(pady=(20, 5))

        # Lista de historial
        frame_lista = tk.Frame(self.root, bg="#1a1a1a")
        frame_lista.pack(pady=5, padx=20, fill=tk.BOTH, expand=True)

        self.lista_historial = tk.Listbox(
            frame_lista,
            bg="#2a2a2a",
            fg="#ffffff",
            selectbackground="#00ff88",
            selectforeground="#000000",
            font=("Consolas", 10),
            height=10,
        )
        self.lista_historial.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(frame_lista, command=self.lista_historial.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.lista_historial.config(yscrollcommand=scrollbar.set)

        # Botones inferiores
        frame_botones = tk.Frame(self.root, bg="#1a1a1a")
        frame_botones.pack(pady=15)

        btn_ver = tk.Button(
            frame_botones,
            text="Ver reporte seleccionado",
            bg="#333333",
            fg="#ffffff",
            font=("Segoe UI", 10),
            command=self._ver_reporte,
        )
        btn_ver.pack(side=tk.LEFT, padx=10)

        btn_salir = tk.Button(
            frame_botones,
            text="Salir",
            bg="#333333",
            fg="#ffffff",
            font=("Segoe UI", 10),
            command=self.root.quit,
        )
        btn_salir.pack(side=tk.LEFT, padx=10)

        # Estado
        self.lbl_estado = tk.Label(
            self.root,
            text="Listo",
            bg="#1a1a1a",
            fg="#888888",
            font=("Segoe UI", 9),
        )
        self.lbl_estado.pack(pady=5)

    def _ejecutar_escaneo(self):
        self.lbl_estado.config(text="Escaneando...", fg="#00ff88")
        self.root.update()

        try:
            # Verificar que existan los archivos de datos
            if not os.path.exists(DATA_FEEDS):
                raise FileNotFoundError(f"No se encontró: {DATA_FEEDS}")
            if not os.path.exists(DATA_INVENTARIO):
                raise FileNotFoundError(f"No se encontró: {DATA_INVENTARIO}")

            # Cargar datos
            with open(DATA_FEEDS, "r", encoding="utf-8") as f:
                feeds = json.load(f)
            with open(DATA_INVENTARIO, "r", encoding="utf-8") as f:
                inventario = json.load(f)

            # Pipeline
            hallazgos = extraer_iocs(feeds["reportes"])
            gaps = detectar_gaps(hallazgos, inventario)
            metadatos = {"fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

            # Generar reporte
            carpeta = generar_reporte(gaps, metadatos, HISTORIAL_DIR)

            self.lbl_estado.config(
                text=f"Escaneo completo: {len(gaps)} gaps detectados",
                fg="#00ff88",
            )
            self._cargar_historial()
            messagebox.showinfo(
                "Éxito",
                f"Escaneo terminado.\nGaps detectados: {len(gaps)}\n\n"
                f"Reporte guardado en:\n{carpeta}",
            )

        except Exception as e:
            self.lbl_estado.config(text="Error en el escaneo", fg="#ff4444")
            messagebox.showerror(
                "Error",
                f"Ocurrió un error:\n\n{str(e)}\n\n"
                f"Asegúrate de estar ejecutando desde la carpeta del proyecto.",
            )

    def _cargar_historial(self):
        self.lista_historial.delete(0, tk.END)
        try:
            escaneos = listar_escaneos(HISTORIAL_DIR)
            for e in escaneos:
                texto = f"{e['fecha']} | {e['total_gaps']} gaps | {e['carpeta']}"
                self.lista_historial.insert(tk.END, texto)
        except Exception as e:
            self.lbl_estado.config(text="Error cargando historial", fg="#ff4444")
            messagebox.showerror("Error", f"No se pudo cargar el historial:\n{str(e)}")

    def _ver_reporte(self):
        seleccion = self.lista_historial.curselection()
        if not seleccion:
            messagebox.showwarning("Aviso", "Selecciona un escaneo de la lista")
            return

        indice = seleccion[0]
        try:
            escaneos = listar_escaneos(HISTORIAL_DIR)
            escaneo = escaneos[indice]
            ruta_html = escaneo["ruta_html"]

            if os.path.exists(ruta_html):
                webbrowser.open(f"file://{ruta_html}")
            else:
                messagebox.showerror("Error", "No se encontró el archivo reporte.html")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo abrir el reporte:\n{str(e)}")


if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = AppThreatHunting(root)
        root.mainloop()
    except Exception as e:
        # Si falla algo crítico, mostrar consola de error en Windows
        import traceback
        traceback.print_exc()
        input("\nPresiona Enter para salir...")
