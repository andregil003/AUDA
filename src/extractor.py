"""
Módulo: extractor.py
Responsable: diego
Función: Extrae IOCs y técnicas de los reportes de seguridad.
Entrada: lista de reportes (JSON)
Salida: lista de hallazgos normalizados
"""

def extraer_iocs(reportes):
    """
    Recibe una lista de reportes y devuelve una lista de hallazgos
    con IOCs y técnicas extraídas.
    """
    hallazgos = []
    for reporte in reportes:
        hallazgo = {
            "reporte_id": reporte.get("id"),
            "titulo": reporte.get("titulo"),
            "tipo_amenaza": reporte.get("tipo_amenaza"),
            "severidad": reporte.get("severidad"),
            "iocs": reporte.get("iocs", []),
            "tecnicas_mitre": reporte.get("tecnicas_mitre", []),
            "software_afectado": reporte.get("software_afectado", []),
            "sistemas_operativos": reporte.get("sistemas_operativos", []),
            "extensiones_afectadas": reporte.get("extensiones_afectadas", []),
        }
        hallazgos.append(hallazgo)
    return hallazgos

if __name__ == "__main__":
    import json
    with open("../data/feeds_simulados.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    resultado = extraer_iocs(data["reportes"])
    print(f"Hallazgos extraídos: {len(resultado)}")
    for h in resultado:
        print(f"- {h['reporte_id']}: {h['titulo']} ({h['severidad']})")
