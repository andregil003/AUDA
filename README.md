# AUDA · Panel local de inteligencia de amenazas

Ejecutar `python run.py` (Python con Tkinter). No requiere paquetes externos.

Pegar una URL y pulsar **Generar análisis**. El reporte aparece dentro de la
ventana: métricas, gráfica, dispositivos, evidencia y plan de acción. El historial
se guarda automáticamente en `historial/analisis/*.json` y se puede recuperar desde
el selector, incluso después de reiniciar. No se descarga ni se abre un reporte externo.

## Alcance de esta entrega

- Fuente real: https://security.paloaltonetworks.com/CVE-2024-3400
- Aviso publicado el 12 de abril de 2024, consultado el 24 de octubre de 2026.
- Se utiliza una ficha local verificada; no se descarga el artículo al analizar.
- Ambiente ficticio de seis dispositivos en `data/ambiente_demo.json`.
- Comparación de versiones y hotfixes, producto y configuración GlobalProtect.
- Las demás URLs se registran como pendientes de evaluación. La recolección
  general de noticias y la integración con asistentes corresponden a la siguiente etapa.
- No inspecciona equipos reales. Los resultados son exposiciones potenciales,
  no prueba de infección. Sin coincidencia solo significa fuera del alcance del CVE evaluado.
- Los mínimos de parche son históricos: verificar versiones soportadas y rutas
  de actualización con el fabricante antes de una intervención real.

Validación: `python -m unittest discover -s tests -v`.
