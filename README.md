# AUDA · Threat Hunting para el Hackathon Alaris & UNIS

## 1. Qué es
AUDA es una herramienta de escritorio simple que toma una noticia de seguridad reciente, analiza qué sistemas de una empresa podrían verse afectados y genera un reporte SOC con recomendaciones concretas. Todo funciona localmente con Python y Tkinter, sin necesidad de instalar paquetes externos ni conexión a internet.

## 2. Problema que buscamos resolver
Muchas empresas en Guatemala y la región operan con sistemas desactualizados (Windows 7, Ubuntu Server viejo, Fedora antiguo) y no cuentan con un SOC que les avise cuando sale una nueva vulnerabilidad o campaña de malware que les afecte directamente. Los analistas reciben miles de alertas genéricas pero no saben cuál aplica a su entorno específico.

## 3. Cómo se va a solucionar
El usuario pega una noticia de seguridad (o usa la de ejemplo incluida). El programa actúa como un agente: extrae el tipo de amenaza, el vector de ataque y los sistemas afectados, los compara con un inventario de equipos legacy y genera un reporte HTML bonito con el gap detectado, la acción inmediata y las recomendaciones para el SOC.

## 4. Por qué es importante nuestra solución
Porque convierte información dispersa de internet en una acción concreta para el analista de seguridad. En lugar de revisar cientos de noticias manualmente, el SOC obtiene un reporte claro y visual que dice: "esta noticia de ayer afecta a tu servidor Windows 7 con Adobe Reader viejo, haz esto ahora". Eso reduce el tiempo de respuesta y ayuda a empresas que no pueden pagar un SIEM caro.
