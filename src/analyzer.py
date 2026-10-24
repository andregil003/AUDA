"""
Módulo: analyzer.py
Función: Agente simple que toma una noticia de seguridad y genera un JSON de gap.
Entrada: diccionario con noticia (titulo, texto, tipo_amenaza, severidad)
Salida: diccionario con gap detectado y recomendaciones para el SOC
"""

def analizar_noticia(noticia):
    """
    Recibe una noticia y devuelve un gap estructurado con recomendaciones SOC.
    """
    texto = (noticia.get("texto", "") + " " + noticia.get("titulo", "")).lower()
    tipo = noticia.get("tipo_amenaza", "desconocida")
    severidad = noticia.get("severidad", "media")

    # Extraer palabras clave simples para determinar el vector
    vector = "desconocido"
    if "pdf" in texto:
        vector = "archivo_adjunto_pdf"
    elif "currículum" in texto or "curriculum" in texto or "word" in texto:
        vector = "archivo_adjunto_documento"
    elif "ssh" in texto or "fuerza bruta" in texto:
        vector = "acceso_remoto_ssh"
    elif "imagen" in texto or "png" in texto or "jpg" in texto:
        vector = "archivo_imagen"
    elif "vulnerabilidad" in texto or "cve" in texto:
        vector = "vulnerabilidad_sistema"

    # Recomendaciones SOC según el tipo
    recomendaciones = _generar_recomendaciones(tipo, vector)

    gap = {
        "fecha_analisis": "2026-10-24",
        "noticia_titulo": noticia.get("titulo", ""),
        "noticia_fuente": noticia.get("fuente", ""),
        "tipo_amenaza": tipo,
        "severidad": severidad,
        "vector_identificado": vector,
        "gap_detectado": f"La empresa podría ser vulnerable a {tipo} vía {vector} si no aplica controles.",
        "recomendaciones_soc": recomendaciones,
        "accion_inmediata": _accion_inmediata(tipo),
    }

    return gap


def _generar_recomendaciones(tipo, vector):
    base = [
        "Monitorear alertas relacionadas con este tipo de amenaza en el SIEM.",
        "Capacitar al personal para identificar archivos sospechosos.",
    ]

    if tipo == "malware":
        base += [
            "Actualizar endpoints y software afectado inmediatamente.",
            "Bloquear extensiones de archivo no necesarias en el correo corporativo.",
            "Ejecutar escaneo de malware en equipos que hayan abierto adjuntos recientes.",
        ]
    elif tipo == "exploit":
        base += [
            "Aplicar parches de seguridad críticos en todos los servidores y estaciones.",
            "Deshabilitar macros en documentos de Office por política de grupo.",
            "Revisar exposición de servicios en internet.",
        ]
    elif tipo == "esteganografia":
        base += [
            "Bloquear descarga de imágenes desde dominios no verificados.",
            "Implementar análisis de archivos entrantes en el proxy corporativo.",
        ]
    elif tipo == "vulnerabilidad":
        base += [
            "Inventariar versiones de software y sistemas operativos en uso.",
            "Priorizar parcheo de sistemas expuestos a internet.",
        ]

    return base


def _accion_inmediata(tipo):
    acciones = {
        "malware": "Aislar equipos sospechosos y actualizar antivirus/EDR.",
        "exploit": "Aplicar parche de seguridad crítico lo antes posible.",
        "esteganografia": "Bloquear descarga de imágenes no verificadas en el firewall.",
        "vulnerabilidad": "Desconectar sistemas vulnerables hasta aplicar parche.",
    }
    return acciones.get(tipo, "Revisar la noticia y aplicar controles preventivos según corresponda.")

if __name__ == "__main__":
    import json
    with open("../data/noticia_ejemplo.json", "r", encoding="utf-8") as f:
        noticia = json.load(f)
    gap = analizar_noticia(noticia)
    print(json.dumps(gap, indent=2, ensure_ascii=False))
