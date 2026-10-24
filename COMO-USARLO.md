# 🛡️ Cómo usar Threat Hunting — Guía rápida

**Repositorio:** https://github.com/andregil003/AUDA  
**Evento:** Cyber Hackathon by Alaris & UNIS (24 de octubre de 2026)

---

## 1. Qué necesitas

- Una computadora con **Python 3 instalado** (Windows, Linux o Mac)
- No necesitas instalar nada más. Tkinter viene incluido con Python.
- No necesitas internet para usarlo (los datos vienen embebidos).

---

## 2. Cómo bajar el proyecto

### Opción A: Clonar con Git
```bash
git clone https://github.com/andregil003/AUDA.git
cd AUDA
```

### Opción B: Descargar ZIP
1. Ve a https://github.com/andregil003/AUDA
2. Haz clic en **Code** → **Download ZIP**
3. Descomprime la carpeta en tu computadora

---

## 3. Cómo ejecutar la aplicación

### Desde la interfaz (más fácil)
Busca el archivo **`run.py`** dentro de la carpeta del proyecto y dale **doble clic**.

Se abrirá una ventana negra con el título **"Threat Hunting - Detección de Gaps"**.

### Desde la terminal (si no abre con doble clic)
```bash
cd AUDA
python3 run.py
```

---

## 4. Cómo usar la ventana

La ventana tiene 4 elementos:

| Elemento | Qué hace |
|----------|----------|
| **Título** | Muestra el nombre de la herramienta |
| **Botón "Escanear ahora"** | Inicia el análisis de seguridad |
| **Lista "Historial de escaneos"** | Muestra los escaneos previos que has hecho |
| **Botón "Ver reporte seleccionado"** | Abre el reporte HTML de un escaneo en tu navegador |
| **Botón "Salir"** | Cierra la aplicación |

---

## 5. Cómo hacer un escaneo (paso a paso)

1. Abre la aplicación (doble clic en `run.py`)
2. Haz clic en el botón verde **"Escanear ahora"**
3. Espera unos segundos. Verás un mensaje que dice cuántos gaps se detectaron
4. El escaneo se guarda automáticamente en la lista del historial
5. Selecciona un escaneo de la lista y haz clic en **"Ver reporte seleccionado"**
6. Se abrirá un archivo HTML en tu navegador con la tabla de resultados

---

## 6. Qué verás en el reporte

El reporte HTML muestra una tabla con:

- **Reporte:** ID del reporte de seguridad (ej: RPT-001)
- **Título:** Qué amenaza se detectó (ej: "Malware en PDFs")
- **Sistema afectado:** Nombre de la computadora o servidor vulnerable
- **Sistema operativo:** Ej: Windows 7, Ubuntu Server 16.04
- **Severidad:** Crítica, Alta o Media
- **Acción sugerida:** Qué hacer para corregirlo

---

## 7. Dónde quedan los archivos

Cada vez que haces un escaneo, se crea una carpeta nueva dentro de `historial/`:

```
historial/
└── escaneo_2026-10-24_12-30-45/
    ├── reporte.html   ← Abre este en tu navegador
    ├── datos.json     ← Datos crudos del escaneo
    └── resumen.txt    ← Resumen de texto plano
```

Puedes volver a abrir cualquier reporte anterior desde la lista del historial.

---

## 8. Solución de problemas

| Problema | Solución |
|----------|----------|
| No se abre la ventana al dar doble clic | Abre una terminal, ve a la carpeta del proyecto y escribe: `python3 run.py` |
| Dice que no encuentra Python | Instala Python 3 desde https://python.org y vuelve a intentar |
| No aparecen escaneos en el historial | Haz al menos un escaneo primero (clic en "Escanear ahora") |
| El reporte HTML no se abre | Asegúrate de tener un navegador instalado (Chrome, Firefox, Edge, Safari) |

---

## 9. Para el hackathon (demo de 2 minutos)

1. Abre la app
2. Haz clic en "Escanear ahora"
3. Muestra la lista de gaps detectados
4. Abre el reporte HTML y muestra la tabla
5. Explica: "Esto detecta amenazas recientes en sistemas viejos de la empresa"

---

## 10. ¿Necesitas ayuda?

Si algo no funciona, avisa a Andre Gil (dueño del repositorio) o revisa que tengas Python 3 instalado correctamente.

---

*Guía de usuario — Repositorio AUDA — Octubre 2026*
