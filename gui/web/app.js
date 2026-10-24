'use strict';
const $ = (selector) => document.querySelector(selector);
const esc = (value) => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const token = $('meta[name="auda-token"]').content;
const labels = {expuesto:'Gap detectado',sin_coincidencia:'Sin coincidencia',pendiente:'Por verificar'};
const colors = {expuesto:'red',sin_coincidencia:'green',pendiente:'amber'};
let boot, report, sourceFilter='todos', statusFilter='todos', search='', view='analisis', toastTimer, lastFocus;
const date = v => new Intl.DateTimeFormat('es-GT',{dateStyle:'medium',timeZone:'America/Guatemala'}).format(new Date(v.length===10?v+'T12:00:00-06:00':v));
const badge = (text, color='neutral') => `<span class="pill ${color}">${esc(text)}</span>`;

async function api(path, data) {
  const response = await fetch(path, data ? {method:'POST',headers:{'Content-Type':'application/json','X-AUDA-Token':token},body:JSON.stringify(data)} : {});
  const result = await response.json();
  if(!response.ok) throw new Error(result.error || 'No se pudo completar la operación.');
  return result;
}
function toast(text) { $('#toast').textContent=text; $('#toast').hidden=false; clearTimeout(toastTimer); toastTimer=setTimeout(()=>$('#toast').hidden=true,4200); }
function go(next) {
  view=next;
  document.querySelectorAll('.view').forEach(el=>el.hidden=el.id!==`view-${next}`);
  document.querySelectorAll('.nav').forEach(el=>{el.classList.toggle('active',el.dataset.view===next); el.setAttribute('aria-current',el.dataset.view===next?'page':'false');});
  $('#crumb').textContent={analisis:'Análisis',fuentes:'Noticias verificadas',inventario:'Dispositivos',historial:'Historial local'}[next];
  window.scrollTo({top:0});
}
function urls() { return $('#urls').value.split(/\r?\n/).map(s=>s.trim()).filter(Boolean); }
function countUrls(){ $('#url-count').textContent=`${urls().length} / 3 noticias`; }
function sourceCard(a,i) {
  return `<article class="source-card"><div class="source-top"><span class="source-index">0${i+1}</span>${badge(date(a.fecha))}</div><span class="tiny">${esc(a.editor)}</span><h3>${esc(a.titulo)}</h3><p>${esc(a.resumen)}</p><div class="source-url"><a href="${esc(a.url)}" target="_blank" rel="noopener noreferrer">${esc(a.url)}</a></div><div class="actions"><button class="secondary" data-use="${esc(a.id)}">Añadir noticia</button><button class="text-button" data-copy="${esc(a.id)}">Copiar URL ↗</button></div></article>`;
}
function emptyResults() {
  $('#results').innerHTML=`<div class="empty fade"><div class="section-row"><div><h2>Tres noticias. Tres investigaciones distintas.</h2><p>Enlaces reales de 2026, listos para pegar. Evalúa uno o combínalos en un reporte.</p></div></div><div class="source-grid">${boot.catalogo.map(sourceCard).join('')}</div><div class="callout">Las fichas se verificaron el 24 de octubre de 2026. La aplicación utiliza reglas locales sobre un inventario ficticio; todavía no extrae noticias arbitrarias ni inspecciona tu computadora.</div></div>`;
}
function renderSources() {
  $('#view-fuentes').innerHTML=`<div class="page-heading"><div><p class="eyebrow">BIBLIOTECA / 2026</p><h1>Noticias verificadas.</h1><p class="subtitle">Copia un enlace, pégalo en Análisis y genera su reporte.</p></div></div><div class="source-grid">${boot.catalogo.map(sourceCard).join('')}</div><div class="panel detail-section"><h3>Cómo se utiliza cada fuente</h3><p>La noticia identifica el problema. La regla compara producto, versión y configuración con el inventario simulado. Cada recomendación conserva el enlace que la respalda. Las acciones de operación son una propuesta de AUDA para el demo; deben validarse en el entorno real.</p></div>${boot.catalogo.map(a=>`<div class="report-source"><div><h3>${esc(a.cve)} · Alcance de la regla</h3><p>${esc(a.contexto)}</p><p>Consultado: ${esc(a.consultado)}</p></div><a href="${esc(a.referencias[0])}" target="_blank" rel="noopener noreferrer">Referencia técnica ↗</a></div>`).join('')}`;
}
function renderInventory() {
  $('#view-inventario').innerHTML=`<div class="page-heading"><div><p class="eyebrow">ATLAS / INVENTARIO SIMULADO</p><h1>Conoce el ambiente.</h1><p class="subtitle">${boot.inventario.dispositivos.length} dispositivos de ejemplo. Esta lista no se obtuvo de tu red.</p></div></div><div class="inventory-grid">${boot.inventario.dispositivos.map(d=>`<article class="panel inventory-card"><span class="device-icon">${d.producto==='FortiOS'?'◇':d.producto==='FortiSIEM'?'▤':'▣'}</span><h3>${esc(d.nombre)}</h3><p>${esc(d.producto)} · ${esc(d.version || 'Versión pendiente')}</p><p class="code">${esc(d.ip)}</p><div class="detail-section"><p>${esc(d.rol)}<br>Responsable: ${esc(d.responsable)}</p></div>${badge(d.internet?'Servicio accesible desde internet':'Acceso interno',d.internet?'amber':'neutral')}${'forticloud_sso' in d?`<p class="subtitle">FortiCloud SSO: ${d.forticloud_sso?'habilitado':'deshabilitado'}</p>`:''}</article>`).join('')}</div>`;
}
function renderHistory() {
  $('#view-historial').innerHTML=`<div class="page-heading"><div><p class="eyebrow">PERSISTENCIA LOCAL</p><h1>Tu historial de análisis.</h1><p class="subtitle">Reportes y tareas guardados en esta computadora, disponibles después de reiniciar.</p></div></div>${boot.historial.length?boot.historial.map(r=>`<article class="history-item"><div><h3>${date(r.fecha)} · ${esc(new Date(r.fecha).toLocaleTimeString('es-GT',{timeZone:'America/Guatemala',hour:'2-digit',minute:'2-digit'}))}</h3><p>${esc(r.articulos.map(a=>a.cve || 'Fuente pendiente').join(' / '))}</p>${badge(`${r.resumen.expuestos} equipos con gaps`,'red')} ${badge(`${r.articulos.length} noticias`)}</div><button class="secondary" data-load="${esc(r.id)}">Abrir reporte →</button></article>`).join(''):'<div class="panel"><h2>Tu primer reporte aparecerá aquí.</h2><p class="subtitle">Genera un análisis para guardarlo automáticamente.</p></div>'}<p class="subtitle">Los reportes anteriores de la interfaz Tkinter permanecen en historial/analisis; este workspace utiliza historial/workspace.</p>`;
}
function donut(counts) {
  const total=Object.values(counts).reduce((a,b)=>a+b,0); let offset=0;
  const circles=Object.entries(counts).map(([key,n])=>{const value=total?100*n/total:0; const el=`<circle class="${key}" cx="60" cy="60" r="46" pathLength="100" stroke-dasharray="${value} ${100-value}" stroke-dashoffset="${-offset}"/>`;offset+=value;return el;}).join('');
  return `<div class="chart-content"><svg class="donut" viewBox="0 0 120 120" role="img" aria-label="Distribución de evaluaciones: ${Object.entries(counts).map(([k,n])=>`${n} ${labels[k]}`).join(', ')}"><circle class="track" cx="60" cy="60" r="46"/>${circles}</svg><div class="legend">${Object.entries(counts).map(([k,n])=>`<p><span class="legend-dot ${colors[k]}"></span>${labels[k]}<b>${n}</b></p>`).join('')}</div></div>`;
}
function renderReport() {
  const r=report, s=r.resumen;
  const first=r.hallazgos.find(f=>f.evidencias.length)||r.hallazgos.find(f=>f.estado==='expuesto')||r.hallazgos.find(f=>f.estado==='pendiente');
  $('#results').innerHTML=`<div class="fade"><div class="report-heading"><div><h2>El panorama, con contexto.</h2><p>${date(r.fecha)} · ${esc(r.empresa)} · ${r.articulos.length} noticias</p></div><span class="saved-label">✓ Guardado localmente</span></div>
    <div class="metrics"><div class="metric"><span class="label">Equipos relacionados</span><strong>${s.evaluados}<span class="tiny"> / ${s.equipos}</span></strong><small>Alcance de las noticias elegidas</small></div><div class="metric emphasis"><span class="label">Equipos con gaps</span><strong>${s.expuestos}</strong><small>Versión y configuración</small></div><div class="metric"><span class="label">Con indicios simulados</span><strong>${s.indicios}</strong><small>Requieren investigación</small></div><div class="metric"><span class="label">Por verificar</span><strong>${s.evaluaciones.pendiente}</strong><small>Evaluaciones con datos faltantes</small></div></div>
    ${s.fuentes_pendientes?`<div class="callout warning">${s.fuentes_pendientes} fuente(s) sin ficha verificada. No se evaluó su contenido. Los resultados de abajo corresponden únicamente a las fuentes compatibles.</div>`:''}
    <div class="report-top"><section class="panel"><p class="overline">TU SIGUIENTE PASO</p>${first?`<div class="priority-item"><span class="priority-icon">↗</span><div><h3>${esc(first.dispositivo.nombre)} ${badge(first.prioridad,first.prioridad==='P0'?'red':'amber')}</h3><p>${esc(first.acciones[0].texto)}</p><button class="text-button" data-inspect="${esc(first.id)}">Ver evidencia y plan del equipo →</button></div></div>`:'<h3>No hay gaps identificados por estas reglas.</h3><p class="subtitle">Esto no equivale a una certificación de seguridad. Revisa el alcance y las fuentes pendientes.</p>'}</section><section class="panel"><p class="overline">RESULTADO POR EVALUACIÓN</p>${donut(s.evaluaciones)}<p class="chart-caption">Cada evaluación corresponde a un equipo + una noticia.</p></section></div>
    <div class="report-tabs" role="group" aria-label="Filtrar por noticia"><span class="tab-label">NOTICIA</span><button class="segment ${sourceFilter==='todos'?'active':''}" data-source="todos">Todas</button>${r.articulos.map(a=>`<button class="segment ${sourceFilter===a.id?'active':''}" data-source="${esc(a.id)}">${esc(a.cve||'Fuente pendiente')}</button>`).join('')}</div>
    <section class="panel table-panel"><div class="table-tools"><h2>Equipos y gaps concretos</h2><div><input id="device-search" class="search-input" aria-label="Buscar dispositivo" placeholder="Buscar equipo…" value="${esc(search)}"><select id="status-filter" aria-label="Filtrar estado"><option value="todos">Todos los estados</option>${Object.entries(labels).map(([k,v])=>`<option value="${k}" ${statusFilter===k?'selected':''}>${v}</option>`).join('')}</select></div></div><div class="table-scroll"><table><thead><tr><th>DISPOSITIVO</th><th>ESTADO</th><th>GAP / EVIDENCIA</th><th>RESPONSABLE</th><th><span class="sr-only">Inspeccionar</span></th></tr></thead><tbody id="device-rows"></tbody></table></div><div class="table-footer" id="table-count"></div></section>
    <div class="section-row"><div><h2>La evidencia empieza en la fuente.</h2><p>Noticias reales, reglas locales y trazabilidad por CVE.</p></div></div><div class="report-source-list">${r.articulos.map(a=>`<article class="report-source"><div><h3>${esc(a.titulo)}</h3><p>${esc(a.editor||'Sin ficha')} ${a.fecha?'· '+date(a.fecha):''}</p><p>${esc(a.contexto||a.resumen)}</p></div><a href="${esc(a.url)}" target="_blank" rel="noopener noreferrer">Leer fuente ↗</a></article>`).join('')}</div><div class="callout">La evaluación usa datos simulados. No confirma compromiso. P0 prioriza indicios; P1, gaps detectados; P2, información faltante. La ausencia de indicios en este inventario no demuestra ausencia de intrusión.</div></div>`;
  renderRows();
}
function renderRows() {
  const rows=report.hallazgos.filter(f=>(sourceFilter==='todos'||f.articulo_id===sourceFilter)&&(statusFilter==='todos'||f.estado===statusFilter)&&`${f.dispositivo.nombre} ${f.dispositivo.producto} ${f.cve}`.toLowerCase().includes(search.toLowerCase()));
  $('#device-rows').innerHTML=rows.length?rows.map(f=>`<tr><td><button class="device-button" data-inspect="${esc(f.id)}">${esc(f.dispositivo.nombre)}</button><small>${esc(f.dispositivo.producto)} ${esc(f.dispositivo.version||'sin versión')}</small></td><td>${badge(labels[f.estado],colors[f.estado])}${f.evidencias.length?'<small>◉ Indicios simulados</small>':''}</td><td class="table-reason"><div class="line-clamp">${esc(f.gap)}</div><small>${esc(f.cve)}</small></td><td>${esc(f.dispositivo.responsable)}<small>${esc(f.prioridad)}</small></td><td><button class="arrow-button" data-inspect="${esc(f.id)}" aria-label="Ver plan de ${esc(f.dispositivo.nombre)}">↗</button></td></tr>`).join(''):'<tr><td colspan="5">No hay evaluaciones para este filtro. Las fuentes no compatibles permanecen pendientes.</td></tr>';
  $('#table-count').textContent=`${rows.length} evaluaciones · Selecciona un equipo para ver el motivo, la corrección y cómo verificarla.`;
}
function inspect(id) {
  const f=report.hallazgos.find(x=>x.id===id);if(!f)return;
  const d=f.dispositivo, a=report.articulos.find(a=>a.id===f.articulo_id);
  lastFocus=document.activeElement;
  $('#inspector-content').innerHTML=`<div class="inspector-header"><div><strong>Inspector del equipo</strong><p>${esc(f.cve)} · Datos simulados</p></div><button class="icon-button" id="close-inspector" aria-label="Cerrar inspector">×</button></div><div class="inspector-body"><p class="eyebrow">${esc(d.rol)}</p><h2 id="inspector-title">${esc(d.nombre)}</h2><p class="sub">${esc(d.ip)} · ${esc(d.producto)} ${esc(d.version||'versión desconocida')}</p><div class="inspector-tags">${badge(labels[f.estado],colors[f.estado])}${badge(f.prioridad)}${badge(f.evidencias.length?'Indicios simulados':'Compromiso no evaluado',f.evidencias.length?'amber':'neutral')}</div>
    <dl class="detail-grid"><div><dt>Responsable</dt><dd>${esc(d.responsable)}</dd></div><div><dt>Servicio accesible desde internet</dt><dd>${d.internet?'Sí':'No'}</dd></div><div><dt>Versión observada</dt><dd>${esc(d.version||'Sin dato')}</dd></div><div><dt>Corrección mínima documentada</dt><dd>${esc(f.objetivo||'Por confirmar')}</dd></div>${'forticloud_sso' in d?`<div><dt>FortiCloud SSO</dt><dd>${d.forticloud_sso?'Habilitado':'Deshabilitado'}</dd></div>`:''}</dl>
    <section class="detail-section"><h3>Por qué aparece este equipo</h3><p>${esc(f.gap)}</p></section><section class="detail-section"><h3>Qué podría ocurrir</h3><p>${esc(f.impacto)}</p></section>
    <section class="detail-section"><h3>Evidencia de compromiso</h3>${f.evidencias.length?f.evidencias.map(e=>`<div class="evidence">${esc(e.detalle)}<small>Origen: ${esc(e.origen)}</small></div>`).join(''):'<p>No se aportaron logs ni resultados forenses que confirmen una intrusión. El gap deriva del inventario. Usa el plan para reunir evidencia.</p>'}</section>
    <section class="detail-section"><h3>Plan específico para ${esc(d.nombre)}</h3><p>Marca lo realizado para llevar seguimiento local. El estado del gap no cambia hasta una nueva evaluación con evidencia.</p>${f.acciones.map((task,i)=>`<label class="task ${task.hecho?'done':''}"><input type="checkbox" data-task="${esc(task.id)}" data-finding="${esc(f.id)}" ${task.hecho?'checked':''} aria-label="Marcar tarea: ${esc(task.titulo)}"><span><h4>${i+1}. ${esc(task.titulo)}</h4><p>${esc(task.texto)}</p><small>Responsable: ${esc(task.responsable)}</small></span></label>`).join('')}</section>
    <section class="detail-section"><h3>Regla y fuente</h3><p>${esc(a.contexto)}</p><a class="source-link" href="${esc(f.fuente)}" target="_blank" rel="noopener noreferrer">${esc(a.editor)} · Leer noticia ↗</a><p class="tiny">Ficha consultada: ${esc(a.consultado)}. Las acciones operativas son un plan propuesto por AUDA, no cambios ejecutados.</p></section></div>`;
  $('#inspector').showModal(); $('#close-inspector').focus();
}
async function refreshHistory(){boot.historial=(await api('/api/bootstrap')).historial;renderHistory();}
async function runAnalysis(){
  const input=urls(); $('#input-error').hidden=true;
  if(!input.length||input.length>3){$('#input-error').textContent='Agrega de una a tres URLs, una por línea.';$('#input-error').hidden=false;return;}
  const button=$('#analyze');button.disabled=true;button.textContent='Evaluando…';
  try{report=await api('/api/analyze',{urls:input});sourceFilter=statusFilter='todos';search='';renderReport();await refreshHistory();toast('Reporte guardado en esta computadora.');}
  catch(error){$('#input-error').textContent=error.message;$('#input-error').hidden=false;}
  finally{button.disabled=false;button.innerHTML='Generar análisis <span>↗</span>';}
}
document.addEventListener('click',async event=>{
  const b=event.target.closest('button');if(!b)return;
  try{
    if(b.dataset.view)go(b.dataset.view);
    if(b.dataset.use){const a=boot.catalogo.find(a=>a.id===b.dataset.use);const list=urls();if(!list.includes(a.url)){if(list.length>=3)return toast('Ya tienes tres noticias. Quita una URL para añadir otra.');list.push(a.url);}$('#urls').value=list.join('\n');countUrls();go('analisis');$('#urls').focus();}
    if(b.dataset.copy){const a=boot.catalogo.find(a=>a.id===b.dataset.copy);await navigator.clipboard.writeText(a.url);toast('URL copiada. Pégala en la barra de noticias.');}
    if(b.dataset.inspect)inspect(b.dataset.inspect);
    if(b.dataset.source){sourceFilter=b.dataset.source;renderReport();}
    if(b.dataset.load){report=await api('/api/report/'+encodeURIComponent(b.dataset.load));sourceFilter=statusFilter='todos';search='';$('#urls').value=report.articulos.map(a=>a.entrada||a.url).join('\n');countUrls();renderReport();go('analisis');toast('Reporte y tareas recuperados.');}
    if(b.id==='use-three'){$('#urls').value=boot.catalogo.map(a=>a.url).join('\n');countUrls();$('#urls').focus();}
    if(b.id==='analyze')await runAnalysis();
    if(b.id==='close-inspector')$('#inspector').close();
    if(b.id==='focus-search'){go('analisis');$('#urls').focus();}
    if(b.id==='theme-toggle'){document.body.classList.toggle('dark');localStorage.setItem('auda-theme',document.body.classList.contains('dark')?'dark':'light');}
  }catch(error){toast(error.message || 'No se pudo completar la operación.');}
});
document.addEventListener('input',e=>{if(e.target.id==='urls')countUrls();if(e.target.id==='device-search'){search=e.target.value;renderRows();}});
document.addEventListener('change',async e=>{
  if(e.target.id==='status-filter'){statusFilter=e.target.value;renderRows();}
  if(e.target.dataset.task){const checkbox=e.target, done=checkbox.checked;checkbox.disabled=true;try{report=await api('/api/action',{report_id:report.id,finding_id:checkbox.dataset.finding,action_id:checkbox.dataset.task,done});checkbox.closest('.task').classList.toggle('done',done);renderReport();toast('Tarea guardada. La evaluación del gap se mantiene.');}catch(error){checkbox.checked=!done;toast(error.message);}finally{checkbox.disabled=false;}}
});
$('#inspector').addEventListener('close',()=>{if(lastFocus?.isConnected)lastFocus.focus();else $('#analyze').focus();});
$('#inspector').addEventListener('click',e=>{if(e.target===$('#inspector')){const r=e.target.getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)e.target.close();}});
document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();go('analisis');$('#urls').focus();}if((e.ctrlKey||e.metaKey)&&e.key==='Enter'&&!$('#analyze').disabled){e.preventDefault();runAnalysis();}});
async function init(){try{if(localStorage.getItem('auda-theme')==='dark')document.body.classList.add('dark');boot=await api('/api/bootstrap');renderSources();renderInventory();renderHistory();emptyResults();countUrls();}catch(error){$('#input-error').textContent='No se pudo abrir el workspace: '+error.message;$('#input-error').hidden=false;$('#analyze').disabled=true;}}
init();
