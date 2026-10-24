"""
Módulo: analyzer.py
Función: Agente de automatización para SOC.
Toma una noticia/vulnerabilidad reciente y genera un boletín estructurado
con el impacto en el entorno de la empresa y acciones inmediatas.
"""

import json
from datetime import datetime


def analizar_amenaza(noticia, inventario):
    """
    Recibe una noticia de vulnerabilidad y el inventario de la empresa.
    Devuelve un boletín SOC con gaps, impacto y acciones.
    """
    texto = (noticia.get("descripcion", "") + " " + noticia.get("titulo", "")).lower()
    tipo = noticia.get("tipo_amenaza", "desconocida")
    severidad = noticia.get("severidad", "media")
    software_afectado = noticia.get("software_afectado", [])

    # Buscar qué sistemas de la empresa están en riesgo
    sistemas_en_riesgo = []
    for sistema in inventario.get("sistemas", []):
        software_sistema = [s.lower() for s in sistema.get("software_instalado", [])]
        for sw in software_afectado:
            if sw.lower() in software_sistema:
                sistemas_en_riesgo.append({
                    "nombre": sistema["nombre"],
                    "sistema_operativo": sistema["sistema_operativo"],
                    "software_coincidente": sw,
                    "rol": sistema.get("rol", ""),
                })
                break

    # Generar acciones según severidad y tipo
    acciones = _generar_acciones(tipo, severidad, sistemas_en_riesgo)

    boletin = {
        "fecha_generacion": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "noticia_titulo": noticia.get("titulo", ""),
        "noticia_fuente": noticia.get("fuente", ""),
        "tipo_amenaza": tipo,
        "severidad": severidad,
        "vector": noticia.get("vector", ""),
        "iocs": noticia.get("iocs", []),
        "sistemas_en_riesgo": sistemas_en_riesgo,
        "total_sistemas_afectados": len(sistemas_en_riesgo),
        "acciones_inmediatas": acciones["inmediatas"],
        "acciones_corto_plazo": acciones["corto_plazo"],
        "recomendacion_soc": acciones["recomendacion"],
    }

    return boletin


def _generar_acciones(tipo, severidad, sistemas_en_riesgo):
    inmediatas = []
    corto_plazo = []
    recomendacion = ""

    if severidad == "critica":
        inmediatas.append("Aislar sistemas afectados de la red si es posible.")
        inmediatas.append("Aplicar parche de emergencia o actualizar software vulnerable.")
        corto_plazo.append("Revisar logs de los últimos 30 días en busca de explotación.")
        corto_plazo.append("Implementar reglas de WAF/IDS para bloquear explotación conocida.")
        recomendacion = "Tratar como prioridad crítica. El SOC debe monitorear activamente explotación en tiempo real."
    elif severidad == "alta":
        inmediatas.append("Evaluar exposición de los sistemas afectados.")
        inmediatas.append("Programar parcheo en la próxima ventana de mantenimiento.")
        corto_plazo.append("Validar parche en entorno de prueba antes de producción.")
        recomendacion = "Priorizar parcheo en los próximos 7 días."
    else:
        inmediatas.append("Documentar la vulnerabilidad en el inventario de riesgos.")
        corto_plazo.append("Incluir en ciclo normal de parcheo.")
        recomendacion = "Monitorear y parchear en ciclo regular."

    if sistemas_en_riesgo:
        inmediatas.insert(0, f"Notificar a los dueños de {len(sistemas_en_riesgo)} sistema(s) afectado(s).")

    return {
        "inmediatas": inmediatas,
        "corto_plazo": corto_plazo,
        "recomendacion": recomendacion,
    }

if __name__ == "__main__":
    with open("../data/noticia_ejemplo.json", "r", encoding="utf-8") as f:
        noticia = json.load(f)
    with open("../data/inventario_empresa.json", "r", encoding="utf-8") as f:
        inventario = json.load(f)
    boletin = analizar_amenaza(noticia, inventario)
    print(json.dumps(boletin, indent=2, ensure_ascii=False))
