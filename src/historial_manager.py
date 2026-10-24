"""
Módulo: historial_manager.py
Responsable: uriel
Función: Lista escaneos previos y lee reportes guardados.
"""

import os
import json
from datetime import datetime


def listar_escaneos(ruta_historial="historial"):
    """
    Devuelve una lista de diccionarios con info de cada escaneo previo,
    ordenados del más reciente al más antiguo.
    """
    if not os.path.exists(ruta_historial):
        return []

    escaneos = []
    for carpeta in os.listdir(ruta_historial):
        ruta_carpeta = os.path.join(ruta_historial, carpeta)
        if not os.path.isdir(ruta_carpeta):
            continue
        ruta_datos = os.path.join(ruta_carpeta, "datos.json")
        if os.path.exists(ruta_datos):
            with open(ruta_datos, "r", encoding="utf-8") as f:
                datos = json.load(f)
            escaneos.append({
                "carpeta": carpeta,
                "fecha": datos.get("fecha", carpeta),
                "total_gaps": datos.get("total_gaps", 0),
                "ruta_html": os.path.join(ruta_carpeta, "reporte.html"),
            })

    escaneos.sort(key=lambda x: x.get("fecha", ""), reverse=True)
    return escaneos


def leer_resumen(ruta_historial="historial", nombre_carpeta=None):
    """
    Lee el resumen.txt de un escaneo específico.
    """
    if not nombre_carpeta:
        return None
    ruta = os.path.join(ruta_historial, nombre_carpeta, "resumen.txt")
    if os.path.exists(ruta):
        with open(ruta, "r", encoding="utf-8") as f:
            return f.read()
    return None

if __name__ == "__main__":
    escaneos = listar_escaneos()
    print(f"Escaneos previos: {len(escaneos)}")
    for e in escaneos:
        print(f"- {e['carpeta']}: {e['total_gaps']} gaps")
