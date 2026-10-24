"""
Módulo: report_generator.py
Función: Genera un reporte HTML bonito y profesional para el SOC.
Entrada: diccionario con el gap
Salida: archivo HTML listo para abrir en el navegador
"""

import os
import json
from datetime import datetime


def generar_reporte_html(gap, ruta_salida="reporte_soc.html"):
    """
    Crea un archivo HTML con diseño moderno, tema oscuro y recomendaciones SOC.
    """
    json_formateado = json.dumps(gap, indent=2, ensure_ascii=False)

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte SOC - Threat Hunting</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #f8fafc;
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        .header {{
            background: linear-gradient(90deg, #00ff88 0%, #00cc6a 100%);
            padding: 30px;
            border-radius: 12px 12px 0 0;
            text-align: center;
        }}
        .header h1 {{ color: #000000; font-size: 28px; margin-bottom: 10px; }}
        .header p {{ color: #000000; font-size: 16px; }}
        .content {{ background: #ffffff1a; padding: 30px; border-radius: 0 0 12px 12px; border: 1px solid #334155; }}
        .badge {{
            display: inline-block;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
            margin-bottom: 15px;
        }}
        .badge.critica {{ background: #ef4444; color: white; }}
        .badge.alta {{ background: #f59e0b; color: white; }}
        .badge.media {{ background: #eab308; color: #000; }}
        .badge.baja {{ background: #10b981; color: white; }}
        .card {{
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        .card h2 {{ color: #00ff88; margin-bottom: 15px; font-size: 20px; }}
        .card p {{ color: #cbd5e1; margin-bottom: 10px; }}
        .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        @media (max-width: 600px) {{ .grid {{ grid-template-columns: 1fr; }} }}
        ul {{ margin-left: 20px; margin-bottom: 15px; }}
        li {{ color: #94a3b8; margin-bottom: 8px; }}
        li strong {{ color: #f8fafc; }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding: 20px;
            color: #64748b;
            font-size: 14px;
            border-top: 1px solid #334155;
        }}
        .json-box {{
            background: #000000;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 15px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 12px;
            color: #00ff88;
            overflow-x: auto;
            margin-top: 15px;
            white-space: pre-wrap;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Reporte de Threat Hunting - SOC</h1>
            <p>Análisis automático de amenaza reciente y recomendaciones para el Centro de Operaciones de Seguridad</p>
        </div>

        <div class="content">
            <div class="badge {gap['severidad']}">Severidad: {gap['severidad'].upper()}</div>

            <div class="card">
                <h2>📰 Noticia Analizada</h2>
                <p><strong>Título:</strong> {gap['noticia_titulo']}</p>
                <p><strong>Fuente:</strong> {gap['noticia_fuente']}</p>
                <p><strong>Tipo de amenaza:</strong> {gap['tipo_amenaza']}</p>
                <p><strong>Vector identificado:</strong> {gap['vector_identificado']}</p>
            </div>

            <div class="card">
                <h2>⚠️ Gap Detectado</h2>
                <p>{gap['gap_detectado']}</p>
            </div>

            <div class="card">
                <h2>🚨 Acción Inmediata</h2>
                <p style="color: #f87171; font-weight: bold;">{gap['accion_inmediata']}</p>
            </div>

            <div class="card">
                <h2>📋 Recomendaciones para el SOC</h2>
                <ul>
                    {"".join(f"<li><strong>{r}</strong></li>" for r in gap['recomendaciones_soc'])}
                </ul>
            </div>

            <div class="card">
                <h2>📦 JSON Generado (Agente)</h2>
                <div class="json-box">{json_formateado}</div>
            </div>
        </div>

        <div class="footer">
            Generado por Threat Hunting Tool - Hackathon Alaris & UNIS | {datetime.now().strftime('%d/%m/%Y %H:%M')}
        </div>
    </div>
</body>
</html>"""

    with open(ruta_salida, "w", encoding="utf-8") as f:
        f.write(html)

    return ruta_salida

if __name__ == "__main__":
    gap_ejemplo = {
        "fecha_analisis": "2026-10-24",
        "noticia_titulo": "Malware en PDFs",
        "noticia_fuente": "BleepingComputer",
        "tipo_amenaza": "malware",
        "severidad": "critica",
        "vector_identificado": "archivo_adjunto_pdf",
        "gap_detectado": "La empresa podría ser vulnerable a malware vía archivo_adjunto_pdf si no aplica controles.",
        "recomendaciones_soc": ["Actualizar endpoints", "Bloquear PDFs no confiables"],
        "accion_inmediata": "Aislar equipos sospechosos",
    }
    ruta = generar_reporte_html(gap_ejemplo, "reporte_prueba.html")
    print(f"Reporte generado: {ruta}")
