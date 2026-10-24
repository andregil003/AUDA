# 📋 Instrucciones del equipo — Hackathon Alaris & UNIS

**Repo:** `andregil003/AUDA`  
**Integrantes:** andreGil, lemus, diego, uriel  
**Fecha del hackathon:** 24 de octubre de 2026  
**Objetivo:** Herramienta de Threat Hunting ligera para sistemas legacy (Windows viejo, Ubuntu Server desactualizado, Fedora antiguo).

---

## 🏗️ Cómo vamos a trabajar

1. **Cada quien clona el repo en su laptop local.**
2. **Cada quien crea su propia rama con su nombre** (ej: `git checkout -b lemus`).
3. **Cada quien trabaja solo en su parte** sin tocar el código de los otros.
4. **Cada quien sube su rama a GitHub** (`git push origin <rama>`).
5. **Andre Gil hace el merge final** de todas las ramas a `main` y resuelve conflictos si los hay.
6. **Nadie hace push directo a `main`** excepto Andre Gil al final.

---

## 👤 Asignación de roles

| Integrante | Rama | Qué construye | Archivos principales |
|------------|------|---------------|---------------------|
| **lemus** | `lemus` | Datos y fuentes | `data/feeds_simulados.json`, `data/inventario_empresa.json`, `src/scraper_playwright.py` |
| **diego** | `diego` | Motor de detección | `src/extractor.py`, `src/correlator.py` |
| **uriel** | `uriel` | Reporte y historial | `src/report_generator.py`, `src/historial_manager.py` |
| **andreGil** | `andreGil` | GUI + integración final | `gui/app.py`, `run.py`, merge de todas las ramas |

---

## 📦 Mínimo viable por cada uno (lo que se espera entregar)

### 🍋 Lemus — Datos y fuentes
**Entrega mínima:**
- `data/feeds_simulados.json`: al menos 5 reportes de seguridad recientes (malware en PDFs, currículums maliciosos, imágenes con código oculto, exploits, vulnerabilidades). Cada reporte debe tener: `id`, `titulo`, `tipo_amenaza`, `severidad`, `software_afectado`, `sistemas_operativos`, `iocs`, `tecnicas_mitre`.
- `data/inventario_empresa.json`: al menos 4 sistemas de empresa legacy (Windows 7, Ubuntu Server 16.04, Fedora 30, Windows Server 2008 R2, etc.) con `nombre`, `sistema_operativo`, `software_instalado`, `rol`.
- `src/scraper_playwright.py` (opcional para el demo, pero entregarlo): script que intente leer feeds reales de seguridad. Si falla o no hay internet, debe usar `data/feeds_simulados.json` como respaldo automático.

**Test individual:**
- Abre los JSON y confirma que se pueden leer con Python (`json.load`).
- Ejecuta el scraper y confirma que devuelve una lista de reportes (reales o simulados).

---

### 🔴 Diego — Motor de detección
**Entrega mínima:**
- `src/extractor.py`: función `extraer_iocs(reportes)` que reciba la lista de reportes y devuelva una lista normalizada con `reporte_id`, `titulo`, `tipo_amenaza`, `severidad`, `iocs`, `tecnicas_mitre`, `software_afectado`, `sistemas_operativos`.
- `src/correlator.py`: función `detectar_gaps(hallazgos, inventario)` que cruce los hallazgos con el inventario de la empresa y devuelva una lista de gaps con `reporte_id`, `titulo`, `sistema_afectado`, `sistema_operativo`, `severidad`, `accion_sugerida`.

**Test individual:**
- Crea un script `test_diego.py` que importe `extractor.py` y `correlator.py`, pase los JSON de lemus, e imprima los gaps detectados por consola.
- Confirma que si un sistema tiene "Adobe Reader 11" y hay un reporte de malware en PDFs para "Adobe Reader 11", se detecta el gap.

---

### 🔵 Uriel — Reporte y historial
**Entrega mínima:**
- `src/report_generator.py`: función `generar_reporte(gaps, metadatos, ruta_historial="historial")` que cree una carpeta en `historial/escaneo_YYYY-MM-DD_HH-MM-SS/` con:
  - `reporte.html` (tabla con los gaps)
  - `datos.json` (datos crudos del escaneo)
  - `resumen.txt` (resumen de texto plano)
- `src/historial_manager.py`: función `listar_escaneos(ruta_historial="historial")` que devuelva lista de escaneos previos ordenados del más reciente al más antiguo.

**Test individual:**
- Crea un script `test_uriel.py` que llame a `generar_reporte` con gaps falsos y verifique que se genera la carpeta con los 3 archivos.
- Confirma que `listar_escaneos()` devuelve al menos un escaneo después de generar uno.

---

### 🟢 Andre Gil — GUI + Integración
**Entrega mínima:**
- `gui/app.py`: ventana gráfica con Tkinter (tema negro simple, sin slop de IA). Debe tener:
  - Botón "Escanear ahora"
  - Lista de historial de escaneos previos
  - Botón "Ver reporte seleccionado" (abre el HTML en el navegador)
  - Botón "Salir"
- `run.py`: doble clic para lanzar la app (no requiere terminal).
- Al final: hace `git merge` de las ramas `lemus`, `diego`, `uriel` a `main` y resuelve conflictos.

**Test individual:**
- Doble clic en `run.py`, se abre la ventana negra.
- Da clic en "Escanear ahora" y ve que aparece un escaneo en la lista.
- Selecciona un escaneo y da clic en "Ver reporte seleccionado" → se abre el HTML en el navegador.

---

## 🔗 Contratos de integración (qué se pasan entre roles)

**De lemus → diego (JSON de reportes):**
```json
[
  {
    "id": "RPT-001",
    "titulo": "Malware en PDFs",
    "tipo_amenaza": "malware",
    "severidad": "critica",
    "software_afectado": ["Adobe Reader 11"],
    "sistemas_operativos": ["Windows 7"],
    "iocs": [],
    "tecnicas_mitre": []
  }
]
```

**De diego → uriel (lista de gaps):**
```json
[
  {
    "reporte_id": "RPT-001",
    "titulo": "Malware en PDFs",
    "sistema_afectado": "PC-Recepcion-01",
    "sistema_operativo": "Windows 7",
    "severidad": "critica",
    "accion_sugerida": "Actualizar Adobe Reader"
  }
]
```

**De uriel → andreGil (carpeta por escaneo):**
```
historial/escaneo_2026-10-24_09-30-00/
├── reporte.html
├── datos.json
└── resumen.txt
```

---

## 🧪 Cómo testa cada uno sin depender de los otros

| Integrante | Test que puede hacer solo |
|------------|---------------------------|
| **Lemus** | Lee los JSON con Python, ejecuta el scraper, confirma que obtiene reportes. |
| **Diego** | Ejecuta `extractor.py` + `correlator.py` con los JSON de lemus, imprime gaps por consola. |
| **Uriel** | Ejecuta `report_generator.py` con gaps falsos, verifica que se crea carpeta con HTML. |
| **Andre Gil** | Ejecuta `run.py`, prueba la ventana negra, escanea, ve historial, abre reporte HTML. |

---

## ⏱️ Cronograma de 5 horas (día del hackathon)

| Tiempo | Acción |
|--------|--------|
| 0:00–0:30 | Reunión rápida (15 min), cada quien se va a su rama y empieza a codar. |
| 0:30–2:00 | Cada quien construye su parte y testa individualmente. |
| 2:00–3:00 | Integración: Andre Gil hace merge de las 3 ramas y prueba el flujo completo. |
| 3:00–4:00 | Arreglar bugs de integración, pulir GUI y reporte HTML. |
| 4:00–5:00 | Ensayo del demo de 2 minutos, grabación de respaldo, listo. |

---

## 🚀 Comandos Git (para cada integrante)

```bash
# Clonar el repo (una sola vez)
git clone https://github.com/andregil003/AUDA.git
cd AUDA

# Crear tu rama con tu nombre
git checkout -b lemus        # o diego, uriel, andreGil

# Trabajar en tus archivos...
git add .
git commit -m "feat: avance de [tu nombre]"

# Subir tu rama a GitHub
git push origin lemus        # o tu rama
```

**Solo Andre Gil hace:**
```bash
git checkout main
git merge lemus
git merge diego
git merge uriel
# Resolver conflictos si los hay
git push origin main
```

---

## 🎨 Diseño de la GUI (requisito de Andre Gil)

- **Tema negro simple:** fondo `#1a1a1a`, texto blanco/gris claro.
- **Sin slop de IA:** no hay chatbot, no hay animaciones innecesarias, no hay modelos de lenguaje pesados.
- **Una ventana, un propósito:** escanear, ver historial, abrir reporte.
- **Doble clic en `run.py`** y se lanza en Windows, Linux y Mac (Python + Tkinter).

---

## ⚠️ Reglas de oro

1. **No toques el código de los demás.** Si necesitas algo de otro compañero, pídeselo y él te lo pasa por su rama.
2. **Cada quien testa su parte antes de subir.**
3. **Andre Gil es el único que hace push a `main`.**
4. **Si algo no funciona, avisa en el grupo antes de romper algo.**

---

*Documento base para el equipo AUDA. Fecha: 24 de octubre de 2026.*
