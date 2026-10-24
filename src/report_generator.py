"""
Módulo: report_generator.py
Función: Genera un boletín HTML bonito y profesional para el SOC.
Entrada: diccionario con el boletín de amenaza
Salida: archivo HTML listo para abrir en el navegador
"""

import os
import json
from datetime import datetime


def generar_boletin_html(boletin, ruta_salida="boletin_soc.html"):
    """
    Crea un archivo HTML con diseño moderno, tema oscuro y recomendaciones SOC.
    """
    json_formateado = json.dumps(boletin, indent=2, ensure_ascii=False)

    # Color según severidad
    color_severidad = {
        "critica": "#ef4444",
        "alta": "#f59e0b",
        "media": "#eab308",
        "baja": "#10b981",
    }.get(boletin.get("severidad", "media"), "#64748b")

    sistemas_html = ""
    for s in boletin.get("sistemas_en_riesgo", []):
        sistemas_html += f"""
        <tr>
            <td>{s['nombre']}</td>
            <td>{s['sistema_operativo']}</td>
            <td>{s['software_coincidente']}</td>
            <td>{s['rol']}</td>
        </tr>
        """
    if not sistemas_html:
        sistemas_html = '<tr><td colspan="4">No se detectaron sistemas afectados en el inventario.</td></tr>'

    iocs_html = ""
    for ioc in boletin.get("iocs", []):
        iocs_html += f"<li><strong>{ioc.get('tipo', '')}:</strong> {ioc.get('valor', '')}</li>"

    acciones_i_html = ""
    for a in boletin.get("acciones_inmediatas", []):
        acciones_i_html += f"<li>{a}</li>"

    acciones_c_html = ""
    for a in boletin.get("acciones_corto_plazo", []):
        acciones_c_html += f"<li>{a}</li>"

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Boletín SOC - {boletin.get('noticia_titulo', '')[:50]}...</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #f8fafc;
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{ max-width: 950px; margin: 0 auto; }}
        .header {{
            background: linear-gradient(90deg, #00ff88 0%, #00cc6a 100%);
            padding: 30px;
            border-radius: 12px 12px 0 0;
            text-align: center;
        }}
        .header h1 {{ color: #000000; font-size: 26px; margin-bottom: 8px; }}
        .header p {{ color: #000000; font-size: 15px; }}
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
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ border: 1px solid #334155; padding: 10px; text-align: left; color: #cbd5e1; }}
        th {{ background: #1e293b; color: #00ff88; }}
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
        .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        @media (max-width: 600px) {{ .grid {{ grid-template-columns: 1fr; }} }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Boletín de Vulnerabilidad - SOC</h1>
            <p>Automatización de amenazas recientes para mantener al SOC actualizado</p>
        </div>

        <div class="content">
            <div class="badge {boletin.get('severidad', 'media')}">Severidad: {boletin.get('severidad', 'media').upper()}</div>

            <div class="card">
                <h2>📰 Amenaza Analizada</h2>
                <p><strong>Título:</strong> {boletin.get('noticia_titulo', '')}</p>
                <p><strong>Fuente:</strong> {boletin.get('noticia_fuente', '')}</p>
                <p><strong>Tipo:</strong> {boletin.get('tipo_amenaza', '')}</p>
                <p><strong>Vector:</strong> {boletin.get('vector', '')}</p>
                <p><strong>Fecha del boletín:</strong> {boletin.get('fecha_generacion', '')}</p>
            </div>

            <div class="card">
                <h2>⚠️ Sistemas de la empresa en riesgo</h2>
                <p>Total afectados: <strong>{boletin.get('total_sistemas_afectados', 0)}</strong></p>
                <table>
                    <thead>
                        <tr><th>Sistema</th><th>Sistema Operativo</th><th>Software vulnerable</th><th>Rol</th></tr>
                    </thead>
                    <tbody>
                        {sistemas_html}
                    </tbody>
                </table>
            </div>

            <div class="grid">
                <div class="card">
                    <h2>🚨 Acciones Inmediatas</h2>
                    <ul>
                        {acciones_i_html}
                    </ul>
                </div>
                <div class="card">
                    <h2>📅 Acciones a Corto Plazo</h2>
                    <ul>
                        {acciones_c_html}
                    </ul>
                </div>
            </div>

            <div class="card">
                <h2>🎯 Recomendación para el SOC</h2>
                <p style="color: #f87171; font-weight: bold; font-size: 16px;">
                    {boletin.get('recomendacion_soc', '')}
                </p>
            </div>

            <div class="card">
                <h2>📦 IOCs</h2>
                <ul>
                    {iocs_html if iocs_html else '<li>No se especificaron IOCs</li>'}
                </ul>
            </div>

            <div class="card">
                <h2>📦 JSON Generado (Agente de Automatización)</h2>
                <div class="json-box">{json_formateado}</div>
            </div>
        </div>

        <div class="footer">
            Generado por AUDA - Automatización para SOC | Hackathon Alaris & UNIS | {datetime.now().strftime('%d/%m/%Y %H:%M')}
        </div>
    </div>
</body>
</html>"""

    with open(ruta_salida, "w", encoding="utf-8") as f:
        f.write(html)

    return ruta_salida

if __name__ == "__main__":
    boletin_ejemplo = {
        "fecha_generacion": "2026-10-24 10:00:00",
        "noticia_titulo": "CVE-2026-44228: Apache Log4j crítica",
        "noticia_fuente": "CISA / NVD",
        "tipo_amenaza": "vulnerabilidad",
        "severidad": "critica",
        "vector": "red",
        "iocs": [{"tipo": "CVE", "valor": "CVE-2026-44228"}, {"tipo": "CVSS", "valor": "9.8"}],
        "sistemas_en_riesgo": [
            {"nombre": "Servidor-Web-01", "sistema_operativo": "Ubuntu Server 20.04", "software_coincidente": "Apache Log4j 2.14.1", "rol": "servidor_web"}
        ],
        "total_sistemas_afectados": 1,
        "acciones_inmediatas": ["Aislar sistemas afectados", "Aplicar parche de emergencia"],
        "acciones_corto_plazo": ["Revisar logs de los últimos 30 días"],
        "recomendacion_soc": "Tratar como prioridad crítica.",
    }
    ruta = generar_boletin_html(boletin_ejemplo, "boletin_prueba.html")
    print(f"Boletín generado: {ruta}")
