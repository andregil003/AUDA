"""
Módulo: correlator.py
Responsable: diego
Función: Cruza hallazgos con el inventario de la empresa y detecta gaps.
Entrada: hallazgos (extractor) + inventario empresa
Salida: lista de gaps detectados
"""

def _sistema_coincide(sistema, hallazgo):
    """
    Devuelve True si el sistema tiene software o SO afectado por el hallazgo.
    """
    software_sistema = [s.lower() for s in sistema.get("software_instalado", [])]
    so_sistema = sistema.get("sistema_operativo", "").lower()

    for sw in hallazgo.get("software_afectado", []):
        if sw.lower() in software_sistema:
            return True

    for so in hallazgo.get("sistemas_operativos", []):
        if so.lower() in so_sistema:
            return True

    return False


def detectar_gaps(hallazgos, inventario):
    """
    Cruza hallazgos con sistemas de la empresa y devuelve gaps.
    """
    gaps = []
    sistemas = inventario.get("sistemas", [])

    for hallazgo in hallazgos:
        for sistema in sistemas:
            if _sistema_coincide(sistema, hallazgo):
                gap = {
                    "reporte_id": hallazgo["reporte_id"],
                    "titulo": hallazgo["titulo"],
                    "sistema_afectado": sistema["nombre"],
                    "sistema_operativo": sistema["sistema_operativo"],
                    "software_coincidente": [
                        sw for sw in hallazgo.get("software_afectado", [])
                        if sw.lower() in [s.lower() for s in sistema.get("software_instalado", [])]
                    ],
                    "severidad": hallazgo["severidad"],
                    "accion_sugerida": _generar_accion(hallazgo),
                }
                gaps.append(gap)

    return gaps


def _generar_accion(hallazgo):
    tipo = hallazgo.get("tipo_amenaza", "")
    if tipo == "malware":
        return "Actualizar software afectado y bloquear extensiones: " + ", ".join(hallazgo.get("extensiones_afectadas", []))
    if tipo == "exploit":
        return "Aplicar parches de seguridad y deshabilitar macros en Office"
    if tipo == "esteganografia":
        return "Actualizar visores de imagen y bloquear archivos PNG/JPG no confiables"
    return "Revisar y aplicar medidas de mitigación según el reporte"

if __name__ == "__main__":
    import json
    with open("../data/feeds_simulados.json", "r", encoding="utf-8") as f:
        feeds = json.load(f)
    with open("../data/inventario_empresa.json", "r", encoding="utf-8") as f:
        inventario = json.load(f)

    from extractor import extraer_iocs
    hallazgos = extraer_iocs(feeds["reportes"])
    gaps = detectar_gaps(hallazgos, inventario)
    print(f"Gaps detectados: {len(gaps)}")
    for g in gaps:
        print(f"- {g['reporte_id']} -> {g['sistema_afectado']} ({g['severidad']})")
