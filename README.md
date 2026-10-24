# auda

AUDA ayuda al SOC a relacionar noticias y vulnerabilidades recientes con sus sistemas y priorizar la respuesta. El panel actual evalúa el equipo donde se ejecuta Python y genera reportes con evidencia y pasos para el SOC; los agentes pueden consultarlos mediante MCP o la API local.

El objetivo es reducir la revisión manual de avisos, identificar los equipos afectados y entregar acciones concretas para resolver los gaps. La evaluación del host y las fuentes oficiales descritas aquí son el flujo principal de `run.py`. El inventario de empresa y la interfaz de escritorio en `gui/soc_panel.py` se conservan como un flujo separado con datos locales.

## Ejecutar

Python 3.10+ en Windows. Sin paquetes externos:

```console
python run.py
```

Se abre el panel en un puerto libre de `127.0.0.1`. Opcional: `python run.py --port 8780 --no-browser`.

## Qué hace

- Lee Windows, edición, versión, build, arquitectura, programas del registro y KBs visibles con `Get-HotFix`. No usa `Win32_Product`, no inspecciona servicios ni modifica el equipo.
- La interfaz mantiene una señal de presencia. Con al menos una pestaña abierta, revisa al inicio y cada 300 segundos. Al cerrar la pestaña informa su salida; si el navegador termina abruptamente, la presencia vence en 90 segundos. Una revisión ya iniciada puede terminar. No instala servicios ni tareas al iniciar Windows.
- Descarga CISA KEV y consulta detalles NVD por CVE. Usa el repositorio oficial `cisagov/kev-data` si CISA falla. No envía nombre del equipo ni el inventario a estas fuentes: descarga el catálogo y consulta identificadores CVE.
- Relaciona identidades explícitas de productos. Solo confirma un rango vulnerable con criterios numéricos simples y el mismo producto. Condiciones complejas quedan pendientes.
- Windows requiere confirmar edición, configuración y parche aplicable: una coincidencia de nombre no prueba que esté vulnerable. Los KBs de `Get-HotFix` no son una lista completa de toda clase de actualizaciones.
- Guarda reportes automáticamente para coincidencias nuevas, incluidas las pendientes de verificar. No duplica un mismo hallazgo con el mismo estado, versión, build y KBs. Los errores de red se muestran y no se convierten en revisiones limpias.
- Cada reporte incluye evidencia, fuente, requisitos, pasos, riesgos, reversión y verificación para un agente. Los comandos provistos son consultas de lectura. No ejecuta correcciones.

## Alcance de las fuentes

CISA KEV cubre vulnerabilidades conocidas como explotadas, no todas las noticias ni todos los CVEs. Cada revisión considera las 20 coincidencias de producto más recientes por fecha de incorporación. Consulta hasta 4 detalles NVD nuevos por ciclo, con caché de 24 horas y un intervalo mínimo de 6,2 segundos entre consultas; los ciclos siguientes continúan enriqueciendo las coincidencias sin caché.

Productos reconocidos: Windows/macOS y una lista explícita de aplicaciones como Chrome, Edge, Firefox, Office, WinRAR, 7-Zip, Acrobat, VS Code, Python y Node.js. La lista completa de programas se muestra, pero solo las identidades implementadas se cruzan automáticamente. Software portable y Store pueden no figurar. En macOS/Linux la recolección actual solo obtiene el OS; la recolección completa es para Windows.

Entrada manual: hasta tres entradas, una por línea: CVEs, texto que los contenga o enlaces de avisos oficiales compatibles. AUDA lee el cuerpo de los avisos HTTPS y extrae hasta 20 CVEs por análisis aunque no estén en la URL. Registra la fuente leída, fecha y huella del contenido; recibir un identificador por sí solo no se presenta como lectura verificada de una página. Si la fuente no se puede leer o no contiene CVEs, informa el motivo. No realiza scraping general ni interpreta cualquier artículo mediante IA.

El lector admite dominios oficiales definidos en `src/article_reader.py`, limita tamaño y tiempo de descarga y valida las redirecciones. Para el aviso CISA de PHP del 21 de octubre de 2026 dispone del boletín oficial del mismo editor en GovDelivery como alternativa si CISA bloquea la lectura; la interfaz identifica qué URL se pudo leer. No se inventan CVEs a partir del título.

Los resultados **sin coincidencia** muestran la evidencia y el motivo, sin tareas ni plan de corrección, incluso al abrir reportes anteriores que ya tengan una revisión favorable. Los casos **pendientes** piden verificar la evidencia faltante antes de proponer una corrección. Una noticia procesada sin producto coincidente no genera un reporte de remediación.

## Agentes: MCP y API local

Con el panel iniciado, la sección **Agentes** muestra la configuración exacta de MCP para ese equipo. Ejemplo:

```json
{
  "mcpServers": {
    "auda": {
      "command": "C:/ruta/python.exe",
      "args": ["C:/ruta/AUDA/agent.py", "--mcp"]
    }
  }
}
```

Herramientas: `auda_environment`, `auda_review`, `auda_status`, `auda_reports`, `auda_report` y `auda_analyze`. Una revisión devuelve un trabajo: consultar estado hasta finalizar. Funciona con clientes que admitan MCP stdio; no conecta por sí solo un proveedor de IA.

CLI:

```console
python agent.py environment
python agent.py review
python agent.py status
python agent.py reports
python agent.py report ID
python agent.py analyze CVE-2025-8088
```

API JSON (cabecera `X-AUDA-Token`):

- `GET /api/environment`, `/api/status`, `/api/reports`, `/api/report/ID`
- `POST /api/review` con `{}`
- `POST /api/analyze` con `{"urls":["CVE-2025-8088"]}`
- `POST /api/action` registra tareas; no ejecuta comandos ni declara corregido un gap.

La conexión y el token se guardan en `historial/runtime.json`, excluido de Git. `agent.py` los lee sin imprimirlos. AUDA solo escucha en loopback. El agente recibe lo que consulta mediante la conexión local; AUDA no manda inventarios a servicios de IA. Los contenidos de fuentes externas son datos, nunca instrucciones ni autorización para actuar.

## Datos y validación

Reportes en `historial/workspace`, detalles públicos en `historial/intelligence`. Los reportes anteriores se conservan; el panel actual muestra solo los asociados al host real. Actualizar una casilla registra seguimiento, no confirma remediación.

```console
python -m unittest discover -s tests -v
```

Fuentes: [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [repositorio oficial](https://github.com/cisagov/kev-data), [NVD](https://nvd.nist.gov/developers/vulnerabilities), [MCP stdio](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports).

## Publicaciones de parches y planes del SOC

La revisión también consulta dos fuentes de fabricante cuando el inventario corresponde:

- **Microsoft MSRC CVRF v3.0**: los dos boletines mensuales más recientes. Exige Windows 10/11, release y arquitectura coincidentes con el producto exacto de MSRC; excluye productos como .NET o Windows Server que solo mencionan Windows en el nombre. Obtiene KB, build corregida, enlace oficial y requisito de reinicio cuando existen.
- **Google Chrome Releases**: los 40 posts más recientes, filtrados a Stable para Windows con versión corregida explícita. No se interpretan versiones Beta, Dev, Android o iOS como parches del Chrome de escritorio. Una rama anterior no demostrada queda pendiente.

Las publicaciones se refrescan cada cinco minutos (caché máxima de 300 segundos). Cada fuente conserva su estado y fecha de publicación; un fallo no implica una revisión limpia y no bloquea necesariamente las demás. La cobertura no incluye todos los fabricantes ni un historial completo de boletines antiguos.

La KB exacta presente confirma la corrección para el producto coincidente. También se reconoce una build igual o posterior en la misma rama de mantenimiento como corrección acumulativa. La ausencia de una KB por sí sola no prueba vulnerabilidad. Si falta build comparable o información de sustitución, queda pendiente.

El panel separa la **evaluación actual** (incluidas correcciones presentes) del **historial de reportes**, que solo crece con coincidencias relevantes nuevas. Los reportes antiguos muestran la evaluación posterior cuando existe. El endpoint `GET /api/evaluations`, la CLI `python agent.py evaluations` y la herramienta MCP `auda_evaluations` entregan ese estado actual.

Cada hallazgo incluye `parche`, `osi` y `plan_soc`. `plan_agente` se conserva como alias compatible. El agente solo consulta y redacta; los pasos de corrección están dirigidos al SOC.

### OSI

La clasificación distingue la capa del problema de las capas de los controles propuestos. Expone términos del aviso, justificación y confianza. Se usa una inferencia explícita, no una clasificación atribuida al fabricante ni evidencia de tráfico real. No se fuerza una capa para fallas locales del kernel, descripciones ambiguas o menciones genéricas de la suite TCP/IP. TLS en capa 6 es una ubicación conceptual de confianza media. Un parche del sistema operativo se presenta como mantenimiento del host, no automáticamente como capa 7.

Prueba de fuentes en vivo (requiere internet): `python tools/check_sources.py`. Las pruebas unitarias usan fixtures y no modifican la PC.
