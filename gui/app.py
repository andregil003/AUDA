"""
Módulo: gui/app.py
Interfaz simple para demo de hackathon.
Flujo: pegar noticia → analizar (agente) → ver reporte SOC bonito.
"""

import tkinter as tk
from tkinter import messagebox, scrolledtext
import webbrowser
import os
import sys
import json

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from analyzer import analizar_noticia
from report_generator import generar_reporte_html

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
DATA_NOTICIA = os.path.join(PROJECT_DIR, "data", "noticia_ejemplo.json")


class AppThreatHunting:
    def __init__(self, root):
        self.root = root
        self.root.title("Threat Hunting - Demo SOC")
        self.root.geometry("700x650")
        self.root.configure(bg="#0f172a")

        self.gap_actual = None
        self.ruta_html = None

        self._construir_interfaz()

    def _construir_interfaz(self):
        # Título
        lbl = tk.Label(
            self.root,
            text="🛡️ Threat Hunting - Demo SOC",
            bg="#0f172a",
            fg="#00ff88",
            font=("Segoe UI", 18, "bold"),
        )
        lbl.pack(pady=15)

        # Instrucciones
        instr = tk.Label(
            self.root,
            text="Pega una noticia de seguridad o usa la de ejemplo:",
            bg="#0f172a",
            fg="#94a3b8",
            font=("Segoe UI", 11),
        )
        instr.pack(pady=(0, 10))

        # Área de texto para la noticia
        self.txt_noticia = scrolledtext.ScrolledText(
            self.root,
            width=80,
            height=10,
            bg="#1e293b",
            fg="#f8fafc",
            insertbackground="#00ff88",
            font=("Consolas", 10),
        )
        self.txt_noticia.pack(pady=5, padx=20)

        # Cargar noticia de ejemplo
        self._cargar_ejemplo()

        # Botones
        frame_btn = tk.Frame(self.root, bg="#0f172a")
        frame_btn.pack(pady=15)

        btn_analizar = tk.Button(
            frame_btn,
            text="🔍 Analizar noticia (Agente)",
            bg="#00ff88",
            fg="#000000",
            font=("Segoe UI", 11, "bold"),
            width=25,
            command=self._analizar,
        )
        btn_analizar.pack(side=tk.LEFT, padx=10)

        btn_reporte = tk.Button(
            frame_btn,
            text="📄 Ver reporte SOC",
            bg="#334155",
            fg="#ffffff",
            font=("Segoe UI", 11),
            width=20,
            command=self._ver_reporte,
            state="disabled",
        )
        btn_reporte.pack(side=tk.LEFT, padx=10)
        self.btn_reporte = btn_reporte

        # Área de resultado JSON
        lbl_json = tk.Label(
            self.root,
            text="JSON generado por el agente:",
            bg="#0f172a",
            fg="#94a3b8",
            font=("Segoe UI", 11),
        )
        lbl_json.pack(pady=(20, 5))

        self.txt_json = scrolledtext.ScrolledText(
            self.root,
            width=80,
            height=12,
            bg="#000000",
            fg="#00ff88",
            insertbackground="#00ff88",
            font=("Consolas", 10),
        )
        self.txt_json.pack(pady=5, padx=20)

        # Estado
        self.lbl_estado = tk.Label(
            self.root,
            text="Listo",
            bg="#0f172a",
            fg="#888888",
            font=("Segoe UI", 9),
        )
        self.lbl_estado.pack(pady=10)

    def _cargar_ejemplo(self):
        try:
            with open(DATA_NOTICIA, "r", encoding="utf-8") as f:
                noticia = json.load(f)
            texto = f"{noticia['titulo']}\n{noticia['texto']}"
            self.txt_noticia.delete("1.0", tk.END)
            self.txt_noticia.insert("1.0", texto)
        except Exception:
            pass

    def _analizar(self):
        texto = self.txt_noticia.get("1.0", tk.END).strip()
        if not texto:
            messagebox.showwarning("Aviso", "Ingresa una noticia para analizar")
            return

        # Construir noticia simple desde el texto
        noticia = {
            "titulo": texto.split("\n")[0][:100],
            "texto": texto,
            "fuente": "Entrada manual",
            "tipo_amenaza": "desconocida",
            "severidad": "media",
        }

        try:
            self.gap_actual = analizar_noticia(noticia)
            self.txt_json.delete("1.0", tk.END)
            self.txt_json.insert("1.0", json.dumps(self.gap_actual, indent=2, ensure_ascii=False))

            # Generar reporte HTML
            self.ruta_html = os.path.join(PROJECT_DIR, "reporte_soc.html")
            generar_reporte_html(self.gap_actual, self.ruta_html)

            self.btn_reporte.config(state="normal")
            self.lbl_estado.config(text="Análisis completo - Reporte SOC generado", fg="#00ff88")
            messagebox.showinfo("Éxito", "Agente analizó la noticia y generó el reporte SOC")

        except Exception as e:
            self.lbl_estado.config(text="Error en el análisis", fg="#ef4444")
            messagebox.showerror("Error", f"No se pudo analizar:\n{str(e)}")

    def _ver_reporte(self):
        if self.ruta_html and os.path.exists(self.ruta_html):
            webbrowser.open(f"file://{self.ruta_html}")
        else:
            messagebox.showwarning("Aviso", "Primero analiza una noticia para generar el reporte")


if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = AppThreatHunting(root)
        root.mainloop()
    except Exception as e:
        import traceback
        traceback.print_exc()
        input("\nPresiona Enter para salir...")
