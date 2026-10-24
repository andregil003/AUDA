"""
Módulo: report_generator.py
Responsable: uriel
Función: Genera reporte HTML por escaneo y guarda en historial.
Entrada: lista de gaps + metadatos del escaneo
Salida: carpeta en historial/ con reporte.html, datos.json, resumen.txt
"""

import os
import json
from datetime import datetime


def generar_reporte(gaps, metadatos, ruta_historial="historial"):
    """
    Crea una carpeta con fecha y hora y guarda el reporte HTML y datos.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    carpeta_escaneo = os.path.join(ruta_historial, f"escaneo_{timestamp}")
    os.makedirs(carpeta_escaneo, exist_ok=True)

    # Guardar datos crudos
    datos = {
        "fecha": metadatos.get("fecha", timestamp),
        "total_gaps": len(gaps),
        "gaps": gaps,
    }
    with open(os.path.join(carpeta_escaneo, "datos.json"), "w", encoding="utf-8") as f:
        json.dump(datos, f, indent=2, ensure_ascii=False)

    # Generar HTML
    html = _construir_html(gaps, metadatos)
    with open(os.path.join(carpeta_escaneo, "reporte.html"), "w", encoding="utf-8") as f:
        f.write(html)

    # Generar resumen de texto
    resumen = _construir_resumen(gaps, metadatos)
    with open(os.path.join(carpeta_escaneo, "resumen.txt"), "w", encoding="utf-8") as f:
        f.write(resumen)

    return carpeta_escaneo


def _construir_html(gaps, metadatos):
    filas = ""
    for g in gaps:
        filas += f"""
        <tr>
            <td>{g['reporte_id']}</td>
            <td>{g['titulo']}</td>
            <td>{g['sistema_afectado']}</td>
            <td>{g['sistema_operativo']}</td>
            <td>{g['severidad'].upper()}</td>
            <td>{g['accion_sugerida']}</td>
        </tr>
        """

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Reporte de Threat Hunting - {metadatos.get('fecha', '')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f4f4f4; }}
        h1 {{ color: #2c3e50; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ccc; padding: 10px; text-align: left; }}
        th {{ background: #2c3e50; color: white; }}
        .critica {{ color: #c0392b; font-weight: bold; }}
        .alta {{ color: #e67e22; font-weight: bold; }}
        .media {{ color: #f1c40f; font-weight: bold; }}
        .resumen {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <h1>🛡️ Reporte de Threat Hunting</h1>
    <div class="resumen">
        <p><strong>Fecha:</strong> {metadatos.get('fecha', '')}</p>
        <p><strong>Total de gaps detectados:</strong> {len(gaps)}</p>
    </div>
    <table>
        <thead>
            <tr>
                <th>Reporte</th>
                <th>Título</th>
                <th>Sistema afectado</th>
                <th>Sistema operativo</th>
                <th>Severidad</th>
                <th>Acción sugerida</th>
            </tr>
        </thead>
        <tbody>
            {filas if filas else '<tr><td colspan="6">No se detectaron gaps en este escaneo.</td></tr>'}
        </tbody>
    </table>
</body>
</html>"""


def _construir_resumen(gaps, metadatos):
    lineas = [
        f"Fecha: {metadatos.get('fecha', '')}",
        f"Total de gaps: {len(gaps)}",
        "",
    ]
    for g in gaps:
        lineas.append(f"- {g['reporte_id']} | {g['sistema_afectado']} | {g['severidad']} | {g['accion_sugerida']}")
    return "\n".join(lineas)

if __name__ == "__main__":
    gaps_ejemplo = [
        {
            "reporte_id": "RPT-001",
            "titulo": "Malware en PDFs",
            "sistema_afectado": "PC-Recepcion-01",
            "sistema_operativo": "Windows 7",
            "severidad": "critica",
            "accion_sugerida": "Actualizar Adobe Reader",
        }
    ]
    ruta = generar_reporte(gaps_ejemplo, {"fecha": "2026-10-24"})
    print(f"Reporte generado en: {ruta}")
