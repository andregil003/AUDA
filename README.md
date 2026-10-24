# AUDA · Automatización para SOC

## 1. Qué es
AUDA es una herramienta de escritorio que automatiza el análisis de vulnerabilidads recientes para el SOC. Toma una noticia o CVE reciente, compara con el inventario de sistemas de la empresa y genera un boletín con los equipos en riesgo, acciones inmediatas y recomendaciones para mantener el SOC actualizado.

## 2. Problema que buscamos resolver
Los SOC reciben cientos de alertas y noticias de vulnerabilidads pero no tienen forma rápida de saber cuáles afectan a sus propios sistemas. Los analistas pierden tiempo revisando manualmente si un CVE nuevo impacta su entorno, especialmente en empresas con sistemas legacy (Windows viejo, Ubuntu Server desactualizado, etc.).

## 3. Cómo se va a solucionar
El usuario ingresa una noticia de vulnerabilidad (o usa la de ejemplo). El agente de AUDA extrae el software afectado, lo cruza con el inventario de la empresa y genera un boletín HTML con: sistemas en riesgo, acciones inmediatas, acciones a corto plazo y recomendación para el SOC. Todo en segundos, sin conexión a internet y sin herramientas complejas.

## 4. Por qué es importante nuestra solución
Porque automatiza un proceso manual y lento del SOC: mantenerse al día con las últimas vulnerabilidads y saber inmediatamente qué sistemas de la empresa están expuestos. Esto reduce el tiempo de respuesta, permite parchear antes de ser explotado y da al SOC una herramienta ligera y gratuita para operar en entornos con recursos limitados.
