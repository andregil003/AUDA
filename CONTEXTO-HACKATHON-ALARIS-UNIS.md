# 🛡️ Contexto de Investigación — Cyber Hackathon by Alaris & UNIS

> Repositorio: `andregil003/AUDA`  
> Evento: **Cyber Hackathon by Alaris & UNIS**  
> Fuente principal: https://luma.com/5ufydec6  
> Fecha del hackathon: **24 de octubre de 2026, 8:00–17:00** (1 día)  
> Lugar: Universidad del Istmo (UNIS), km 19.2 Carretera a Fraijanes, Guatemala  

---

## 1. El evento (resumen ejecutivo)

| Dato | Detalle |
|------|---------|
| **Organizadores** | Alaris Security + Universidad del Istmo (UNIS) |
| **Anfitriones (hosts)** | Ethan Glenny (Chief of Staff, Alaris Security, San Francisco) + Estuardo Antonio Sandoval (Director de Ingeniería en Sistemas, UNIS, Guatemala) |
| **Formato** | Equipos de 2–4 personas (solo también permitido). Build durante el evento. Demo de 2 minutos. |
| **Entregables obligatorios** | (1) Working demo funcional, (2) Technical write-up (problema, solución, arquitectura, tecnologías) |
| **Premios** | 1º: Swag Alaris Guate + 12 meses HTB + spotlight + 1hr sesión carrera con Alaris + certificación. 2º: 6 meses HTB + mención + certificación. 3º: 3 meses HTB + mención + certificación. |
| **Reglas clave** | IA permitida (documentar qué y por qué). Herramientas de terceros permitidas. Datos reales o simulados (citados). No exponer credenciales/API keys. No probar contra sistemas no autorizados. "Keep it simple. Build something meaningful." |
| **Jueces** | Panel internacional (staff de Alaris, perfil CISO, Black Hat/RSA) |

### El reto
> "Choose one task in a security operations centre (SOC) and find a better way to do it."

Ejemplos que dan los organizadores: automatizar phishing triage, conectar alertas relacionadas, construir un timeline de incidentes, o cualquier otro problema que merezca resolverse. Usar IA, codear a mano, open source, o una combinación. Mostrar cómo la solución ayuda a los analistas de seguridad a ahorrar tiempo, tomar mejores decisiones o responder más rápido.

---

## 2. Quiénes son los involucrados (perfiles investigados)

### Alaris Security
- **Qué hacen:** "La primera plataforma autónoma de operaciones, gestión y defensa proactiva de ciberseguridad" (ASO — Autonomous Security Operations). Unifica: Autonomous SOC, EDR, Cloud Detection & Response, GRC Center, Agent Framework y Security Data Graph. Cubren 6 etapas: detection engineering, alert triage, investigation, threat hunting, containment & response, reporting.
- **Lema:** "What SOAR should've been, what AI SOC will become".
- **Fundador/CEO:** David Colombo (investigador de seguridad conocido, hackeo Tesla a los 19, aparece en Bloomberg/Forbes/Reuters).
- **Chief of Staff:** Ethan Glenny (el host en Luma, ex-Casper AI, no es técnico puro, se está formando como technical founder).
- **GitHub org:** `github.com/alaris-security` — solo 2 repos públicos (`alaris-global-detections` con reglas de detección en Python, y `.github`).
- **Stack:** IA/agentes autónomos, graph database propietario, 50+ integraciones (Splunk, Sentinel, Defender, CrowdStrike, Okta, etc.), despliegue cloud/híbrido/on-prem/air-gapped.
- **Sitio:** https://alaris.security/

### Estuardo Antonio Sandoval (host UNIS)
- Automation & Software Manager en Tecnodyne (Guatemala, 12 años). Director de Ingeniería en Sistemas y Ciencias de la Computación y de Electrónica y Telecomunicaciones en UNIS. PhD en Computer Science. Profesor en UNIS desde 2017. Conectado con ciberseguridad (Cyber Games Latam 2024, certificación Cisco).

### UNIS (Universidad del Istmo)
- Universidad privada en Guatemala con programa activo de ciberseguridad: licenciatura con especialización en Ciberseguridad/IA, Maestría en Ciberseguridad (16 meses, enfoque CISO, NIST/ISO 27001/CISM), Academia MikroTik. Es el anfitrión académico del hackathon.

---

## 3. Estado de los SOC a fecha de 2026 (problemas actuales)

### Áreas que siguen sin resolverse bien (faltantes / no tocadas)

| # | Área faltante | Evidencia / Contexto |
|---|--------------|---------------------|
| 1 | **Alert fatigue y agotamiento del analista** | 4,400+ alertas/día en SOC corporativo, 63% sin investigar, 50%+ son falsos positivos, tenure promedio <3 años. Sigue siendo el problema #1 (SANS 2026, ACM Computing Surveys 2025). |
| 2 | **Herramientas dispares y pivoteo manual** | Los analistas saltan entre SIEM, OSINT, endpoints, cloud, correo manualmente. Las herramientas no se hablan entre sí sin integración manual (NDSS 2026, Rapid7 2026). |
| 3 | **IA sin gobernanza ni flujo definido** | 79% de SOCs usa IA/ML, pero solo 36% la ha integrado en un flujo de trabajo definido (SANS 2026). |
| 4 | **Detección de identidad y amenazas en la nube/SaaS** | Falta correlación entre EDR, identidad (Entra ID/Okta), nube y correo. Los ataques abusan de identidad válida; las firmas no lo detectan. |
| 5 | **Threat hunting proactivo vs operación reactiva** | La mayoría de SOCs es reactiva (alert-driven). El hunting requiere tiempo que no tienen por la carga de alertas. |
| 6 | **Falsos positivos en detección conductual** | Anomalías benignas generan ruido; no hay método estándar para afinar baselines por entidad. |

### Tendencias clave 2026

- **Headless SOC** — arquitectura sin UI, operada por agentes vía API/MCP (LimaCharlie, Scanner.dev).
- **Agentic SOC** — agentes LLM (ReAct) que triagean, investigan y responden end-to-end (Elastic AlertZero, Splunk ES AI Triage Agent, oct 2026).
- **SOAR con IA** superando playbooks estáticos.
- **Detección conductual vs signature-based** — capas combinadas, no solo firmas.
- **Desplazamiento del rol humano** — el analista L1 pasa de "recolectar contexto" a "juicio y decisión".

---

## 4. Repos GitHub relevantes (lo que YA existe)

### Bien cubiertas (mucho ruido ya — evitar replicar sin diferenciarse)

| Categoría | Repos representativos |
|-----------|----------------------|
| AI-SOC general / agentes autónomos | `beenuar/AiSOC`, `zhadyz/AI_SOC`, `0xrisec/Agentic-SOC`, `abhishekk-y/ALISS`, `rushanknaik/SentinelAgent-Soc` |
| Phishing triage | `HaythamAbouelfaid/SentinelOps`, `makhembu/phishkit`, `rahx-cyber/phishing-email-analyzer`, `riyamore09/AI-powered-Phishing-Email-Investigation` |
| SOAR open source | `opensoar-hq/opensoar-core`, `Shuffle/Shuffle`, `SecurityBrewery/catalyst`, `TracecatHQ/tracecat` |
| SOC con LLM para triage | `Mario0111/alert-triage-rag`, `rohit-aswal08/AI-SOC-Alert-Framework` |

### Faltantes / subrepresentados (OPORTUNIDAD para el hackathon)

| Área faltante | Por qué es oportunidad |
|--------------|----------------------|
| **Headless SOC puro (API-first, sin dashboard)** | Pocos proyectos operan solo por agentes vía API/MCP. La mayoría aún construye dashboard web. |
| **Incident Timeline Builder específico de seguridad** | Los que existen son genéricos de postmortem de software, no consumen telemetría de seguridad (SIEM, EDR, Wazuh). |
| **Integración nativa con SIEMs populares** | Pocos conectan directamente con Wazuh, Sentinel, Splunk, Elastic como entrada principal. |
| **Respuesta automatizada real con aprobación humana** | La mayoría se queda en triage/investigación; pocas ejecutan contención (isolamiento, bloqueo IP) con human-in-the-loop. |
| **Benchmarks públicos de triage de alertas** | Falta tooling abierto para medir precisión/recall de agentes SOC. |

---

## 5. Escena de ciberseguridad en Guatemala (contexto local)

### Comunidades activas
- ISACA Capítulo Guatemala (ISACA Summit anual, octubre)
- ISC2 Guatemala Chapter (fundado 2020)
- Open Hacking Guatemala (Quetzaltenango)
- Pwned! Con (Ciudad de Guatemala, Teatro Dick Smith)
- NeuroH4ckin9 (Ciudad de Guatemala)
- Antigua Tech Summit (octubre, Antigua Guatemala)
- FIT Universidad Galileo (track de ciberseguridad, Flipper Zero, war driving)

### Empresas con CISO/equipos de seguridad
Claro Empresas (CYBERSAFE 360), Grupo Financiero GyT, CMI, InterBanco, COPA Airlines, Agroamérica, GBM.

### Hackathons previos relacionados
- UNIS + Oracle + Ficohsa (octubre 2021) — UNIS ganó 1ro global
- Universidad Galileo + US Embassy (ciberseguridad)
- CORETIC INNOVA TECH 2026
- OEA CyberChallenge Guatemala

### Entidad reguladora
- INCIBE Guatemala (Instituto Nacional de Ciberseguridad de Guatemala)

---

## 6. Qué valorarían probablemente los jueces (perfil internacional de Alaris)

1. **Impacto real en el analista SOC** — ¿cuánto tiempo ahorra? ¿reduce el "swivel-chair" entre herramientas?
2. **Demo funcional en vivo** — no diapositivas. En 2 minutos, un demo que falle es fatal.
3. **Problema SOC concreto y acotado** — phishing triage, correlación de alertas, timeline de incidentes. No algo genérico de IA.
4. **Arquitectura agente, no "wrapper de LLM"** — los jueces de Alaris construyen agentes autónomos; valorarán un sistema que actúe, no solo responda.
5. **Datos realistas y citados** — regla 5 y 6 del evento.
6. **Responsabilidad** — no exponer credenciales/API keys (regla 7).
7. **Entregables completos** — demo + technical write-up (ambos obligatorios).
8. **Simplicidad y significado** — "Keep it simple. Build something meaningful."

### Estructura sugerida del demo de 2 minutos
- 0:00–0:15 — Problema (dolor del analista SOC)
- 0:15–1:15 — Demo en vivo mostrando el prototipo resolviendo el problema
- 1:15–1:45 — Métrica de impacto (tiempo ahorrado, decisiones mejoradas, respuesta más rápida)
- 1:45–2:00 — Cierre memorable

---

## 7. Recomendaciones estratégicas para el equipo

### Antes del evento
1. **Formar equipo de 3–4 perfiles complementarios:** alguien que entienda operaciones de SOC (triage de phishing, alertas, SIEM), alguien fuerte en código/automatización, alguien en IA/agentes, y alguien que presente bien (el demo de 2 min es decisivo).
2. **Elegir un problema SOC concreto y acotado:** phishing triage, correlación de alertas de SIEM, timeline de incidentes, o enriquecimiento de alertas con threat intelligence. Mejor un problema pequeño resuelto completamente que uno grande a medias.
3. **Preparar datos simulados realistas** de eventos de seguridad (alertas, logs, emails de phishing) y citar su origen (regla 5). Tener un dataset listo para no perder tiempo el día del evento.
4. **Diseñar con arquitectura "agente" no "chatbot":** dado que los jueces son de Alaris (ASO, autonomía), valorar un sistema que actúe, no solo responda. Pensar en detección → triage → investigación → respuesta.
5. **Preparar el technical write-up con anticipación (estructura):** problema, solución, arquitectura, tecnologías, datos usados, limitaciones.

### Durante el hackathon (8am–5pm)
6. **Priorizar un demo funcional sobre funcionalidades:** regla 2 ("Build during the hackathon"). Tener un happy path demostrable antes de las 3:30pm (submission deadline).
7. **No exponer credenciales ni API keys** (regla 7). Usar variables de entorno o mocks.
8. **Documentar el uso de IA** (qué modelo, para qué, por qué) — regla 4. Esto genera confianza con jueces técnicos.
9. **Identificar claramente qué es real y qué es simulado** — regla 6. Los jueces internacionales valorarán la integridad.
10. **Usar el horario completo:** 9:00–12:00 y 12:30–3:30 son build sessions. Las últimas 15 min (3:30–3:45) son para submission y prep de demo.

### En la presentación (3:45–4:30pm, 2 minutos)
11. **Demo en vivo obligatorio** — practicar el flujo exactamente; tener un plan B (grabación) si falla internet/APIs.
12. **Conectar con la misión de Alaris:** autonomía, reducción de MTTR, force multiplier para equipos pequeños de seguridad. Mencionar cómo la solución se alinea con Autonomous SOC.
13. **Traer laptop y cargador** (regla del evento). Probar conectividad en el campus antes.

### Después / relación con los organizadores
14. **Aprovechar la sesión de carrera de 1 hora con Alaris** (premio 1er puesto) — canal directo con el Chief of Staff de una startup de SF.
15. **La suscripción a HTB (12/6/3 meses)** es valiosa para seguir practicando y mejorar perfil técnico.
16. **Mantener contacto con Estuardo Sandoval (UNIS) y Ethan Glenny (Alaris)** — puente entre la escena local y la internacional.

---

## 8. Enlaces y fuentes

### Evento
- https://luma.com/5ufydec6 — Página del evento (fuente principal)
- https://allai.events/event/cyber-hackathon-by-alaris--unis — Listing en AllAI Events
- https://luma.com/alaris.security — Calendario de eventos de Alaris en Luma

### Alaris Security
- https://alaris.security/ — Sitio web
- https://alaris.security/about — Sobre la empresa
- https://alaris.security/articles/2026/03/what-is-autonomous-security-operations — Artículo ASO (Ethan Glenny + David Colombo)
- https://github.com/alaris-security — GitHub org (2 repos públicos)
- https://github.com/david-colombo — GitHub del fundador (9 repos)
- https://linkedin.com/company/alaris-security — LinkedIn empresa
- https://linkedin.com/in/iamethanglenny — LinkedIn Ethan Glenny
- https://github.com/iamethanglenny — GitHub Ethan Glenny (sin repos públicos)

### UNIS
- https://unis.edu.gt/ — Sitio principal
- https://unis.edu.gt/facultad-de-ingenieria/ingenieria-en-sistemas-y-ciencias-de-la-computacion/ — Carrera Sistemas (esp. Ciberseguridad)
- https://virtual.unis.edu.gt/p/maestria-en-ciberseguridad — Maestría en Ciberseguridad
- https://online.unis.edu.gt/blog/unis-y-su-apuesta-por-la-formacion-estrategica-en-ciberseguridad/ — Blog UNIS ciberseguridad
- https://unis.edu.gt/facultad-de-ingenieria/academia-mikrotik-unis/ — Academia MikroTik UNIS

### Escena ciberseguridad Guatemala
- https://isacasummit.org/ — ISACA Summit
- https://www.openhacking.gt/ — Open Hacking Guatemala
- https://www.pwnedcon.com/ — Pwned! Con
- https://www.neuroh4ckin9.com/ — NeuroH4ckin9
- https://antiguatechsummit.com/ — Antigua Tech Summit
- https://www.coretic.gt/ — CORETIC
- https://linkedin.com/company/isc2chaptergt — ISC2 Guatemala Chapter

---

## 9. Próximos pasos sugeridos para el equipo

1. Leer este documento completo y alinearse en el problema a atacar.
2. Definir roles del equipo (SOC, código, IA, presentación).
3. Elegir el stack tecnológico (Python/Node/Go, n8n, Ollama/LLM local, APIs de nube).
4. Preparar dataset simulado de eventos de seguridad antes del 24 de octubre.
5. Diseñar la arquitectura agente y el happy path del demo.
6. Redactar la estructura del technical write-up.

---

*Documento preparado por PUCK para el equipo del repositorio AUDA. Contexto recopilado el 24 de octubre de 2026.*
