"""Panel local AUDA: reporte integrado e historial persistente."""
import tkinter as tk
from tkinter import ttk
import webbrowser
from src.hunting import analyze, history, save, source, STATUSES

BG, PANEL, LINE = '#0b1120', '#141e30', '#28364b'
TEXT, MUTED, ACCENT = '#edf2fb', '#98aac3', '#69e0bd'
COLORS = {STATUSES[0]: '#ff8b8b', STATUSES[1]: ACCENT, STATUSES[2]: '#f3c776'}


class AppThreatHunting:
    def __init__(self, root):
        self.root = root
        root.title('AUDA | Inteligencia de amenazas')
        root.geometry('1200x880')
        root.minsize(1020, 680)
        root.configure(bg=BG)
        self.report = None
        style = ttk.Style(root)
        style.theme_use('clam')
        style.configure('Treeview', background=PANEL, fieldbackground=PANEL, foreground=TEXT,
                        rowheight=36, borderwidth=0, font=('Segoe UI', 10))
        style.configure('Treeview.Heading', background=LINE, foreground=MUTED,
                        font=('Segoe UI', 10, 'bold'), relief='flat')
        style.map('Treeview', background=[('selected', '#2d4960')], foreground=[('selected', TEXT)])
        style.configure('TCombobox', fieldbackground=PANEL, background=LINE, foreground=TEXT,
                        arrowcolor=ACCENT, padding=6)
        style.map('TCombobox', fieldbackground=[('readonly', PANEL)], foreground=[('readonly', TEXT)])
        self._build()
        self._refresh_history()

    def label(self, parent, text, size=11, color=TEXT, bold=False, **kw):
        return tk.Label(parent, text=text, bg=parent.cget('bg'), fg=color,
                        font=('Segoe UI', size, 'bold' if bold else 'normal'), **kw)

    def button(self, parent, text, command, primary=False):
        return tk.Button(parent, text=text, command=command, bg=ACCENT if primary else LINE,
                         fg=BG if primary else TEXT, activebackground='#90efd1', activeforeground=BG,
                         relief='flat', bd=0, padx=18, pady=10, cursor='hand2',
                         font=('Segoe UI', 10, 'bold'))

    def _build(self):
        header = tk.Frame(self.root, bg=BG, padx=28, pady=18)
        header.pack(fill='x')
        self.label(header, 'AUDA', 24, ACCENT, True).pack(side='left')
        self.label(header, '  /  INTELIGENCIA DE AMENAZAS', 10, MUTED).pack(side='left', padx=14)
        self.label(header, '●  LOCAL   /   AMBIENTE SIMULADO', 9, ACCENT).pack(side='right')
        search = tk.Frame(self.root, bg=PANEL, padx=22, pady=18)
        search.pack(fill='x', padx=28)
        self.label(search, 'De una noticia a un plan de acción.', 21, bold=True).pack(anchor='w')
        self.label(search, 'Pega un enlace de seguridad y evalúa su alcance sobre el inventario de la empresa.',
                   color=MUTED).pack(anchor='w', pady=(5, 14))
        row = tk.Frame(search, bg=PANEL)
        row.pack(fill='x')
        self.url = tk.StringVar(value=source()['url'])
        self.entry = tk.Entry(row, textvariable=self.url, bg=BG, fg=TEXT, insertbackground=ACCENT,
                              relief='flat', font=('Segoe UI', 12), highlightthickness=1,
                              highlightbackground=LINE, highlightcolor=ACCENT)
        self.entry.pack(side='left', fill='x', expand=True, ipady=12, padx=(0, 12))
        self.entry.bind('<Return>', lambda e: self._analyze())
        self.button(row, 'Generar análisis  →', self._analyze, True).pack(side='right')
        row2 = tk.Frame(search, bg=PANEL)
        row2.pack(fill='x', pady=(10, 0))
        self.label(row2, 'Caso real: Palo Alto Networks · CVE-2024-3400 · abril 2024', 9, MUTED).pack(side='left')
        self.button(row2, 'Usar ejemplo', lambda: self.url.set(source()['url'])).pack(side='right')
        bar = tk.Frame(self.root, bg=BG, padx=28, pady=12)
        bar.pack(fill='x')
        self.status = self.label(bar, 'Listo · El caso verificado funciona sin conexión.', 10, MUTED)
        self.status.pack(side='left')
        self.history_box = ttk.Combobox(bar, state='readonly', width=34)
        self.history_box.pack(side='right')
        self.history_box.bind('<<ComboboxSelected>>', self._load_history)
        self.label(bar, 'Historial local  ', 10, MUTED).pack(side='right')
        area = tk.Frame(self.root, bg=BG)
        area.pack(fill='both', expand=True, padx=28, pady=(0, 18))
        self.canvas = tk.Canvas(area, bg=BG, highlightthickness=0)
        scroll = ttk.Scrollbar(area, orient='vertical', command=self.canvas.yview)
        scroll.pack(side='right', fill='y')
        self.canvas.pack(side='left', fill='both', expand=True)
        self.canvas.configure(yscrollcommand=scroll.set)
        self.body = tk.Frame(self.canvas, bg=BG)
        self.window = self.canvas.create_window((0, 0), window=self.body, anchor='nw')
        self.body.bind('<Configure>', lambda e: self.canvas.configure(scrollregion=self.canvas.bbox('all')))
        self.canvas.bind('<Configure>', lambda e: self.canvas.itemconfigure(self.window, width=e.width))
        self.root.bind_all('<MouseWheel>', self._wheel)
        self.label(self.body, 'Tu próximo análisis comienza con una fuente.', 22, bold=True).pack(pady=(55, 10))
        self.label(self.body, 'Genera el reporte para ver dispositivos, evidencias y acciones en este panel.', color=MUTED).pack()
        self.label(self.body, 'Fuente real verificada  /  6 dispositivos de ejemplo  /  Guardado automático', 11, ACCENT).pack(pady=20)

    def _wheel(self, event):
        if event.widget.winfo_class() not in ('Treeview', 'TCombobox'):
            self.canvas.yview_scroll(-int(event.delta / 120), 'units')

    def _analyze(self):
        try:
            report = analyze(self.url.get())
        except (ValueError, OSError, KeyError) as exc:
            self.status.config(text=str(exc), fg=COLORS[STATUSES[0]])
            return
        self.render(report)
        try:
            save(report)
            self._refresh_history()
            self.status.config(text='Guardado en esta computadora · Disponible en el historial.', fg=ACCENT)
        except OSError:
            self.status.config(text='Reporte visible; no se pudo guardar. Revisa permisos y espacio.', fg=COLORS[STATUSES[0]])

    def _refresh_history(self):
        self.saved = history()
        self.history_box['values'] = [f"{r['fecha'][:19].replace('T', ' ')} · {r['id'][-8:]}" for r in self.saved]
        self.history_box.set('Seleccionar análisis guardado')

    def _load_history(self, event=None):
        index = self.history_box.current()
        if index >= 0:
            report = self.saved[index]
            self.url.set(report['url'])
            self.render(report)
            self.status.config(text='Reporte recuperado del historial local.', fg=ACCENT)

    def card(self, parent=None):
        return tk.Frame(parent or self.body, bg=PANEL, padx=20, pady=16,
                        highlightthickness=1, highlightbackground=LINE)

    def render(self, report):
        self.report = report
        for widget in self.body.winfo_children():
            widget.destroy()
        ref = report['fuente']
        heading = tk.Frame(self.body, bg=BG)
        heading.pack(fill='x', pady=(8, 14))
        self.label(heading, 'Reporte de exposición', 22, bold=True).pack(side='left')
        self.label(heading, report['fecha'][:19].replace('T', '  '), 10, MUTED).pack(side='right')
        metrics = tk.Frame(self.body, bg=BG)
        metrics.pack(fill='x', pady=(0, 14))
        values = [(len(report['dispositivos']), 'Dispositivos en inventario', TEXT),
                  (report['conteos'][STATUSES[0]], 'Exposiciones potenciales', COLORS[STATUSES[0]]),
                  (report['expuestos_internet'], 'Exposiciones a internet', COLORS[STATUSES[2]]),
                  (report['conteos'][STATUSES[2]], 'Pendientes de verificar', MUTED)]
        for i, (value, title, color) in enumerate(values):
            metrics.columnconfigure(i, weight=1, uniform='metric')
            tile = self.card(metrics)
            tile.grid(row=0, column=i, sticky='nsew', padx=(0 if i == 0 else 7, 0))
            self.label(tile, str(value), 30, color, True).pack(anchor='w')
            self.label(tile, title, 10, MUTED).pack(anchor='w')
        overview = tk.Frame(self.body, bg=BG)
        overview.pack(fill='x', pady=(0, 14))
        overview.columnconfigure(0, weight=3)
        overview.columnconfigure(1, weight=2)
        news = self.card(overview)
        news.grid(row=0, column=0, sticky='nsew', padx=(0, 12))
        self.label(news, '01 / FUENTE Y ALCANCE', 9, ACCENT, True).pack(anchor='w')
        self.label(news, ref['titulo'] if ref else 'Fuente pendiente de procesar', 15, bold=True,
                   wraplength=490, justify='left').pack(anchor='w', pady=(12, 8))
        summary = ref['resumen'] if ref else (
            'El enlace quedó registrado. La extracción automática de noticias se añadirá en la siguiente etapa. '
            'Esta URL aún no tiene una regla verificada; todos los dispositivos quedan por verificar.')
        self.label(news, summary, 11, MUTED, wraplength=490, justify='left').pack(anchor='w')
        if ref:
            self.label(news, f"CVSS {ref['cvss']} · Publicado {ref['publicado']}\nReferencia consultada {ref['verificado']} · Copia local", 10, ACCENT, justify='left').pack(anchor='w', pady=12)
        self.button(news, 'Abrir fuente original ↗', lambda: webbrowser.open(report['url'])).pack(anchor='w', pady=(8, 0))
        chart_card = self.card(overview)
        chart_card.grid(row=0, column=1, sticky='nsew')
        self.label(chart_card, '02 / COBERTURA DEL ANÁLISIS', 9, ACCENT, True).pack(anchor='w')
        self.chart = tk.Canvas(chart_card, bg=PANEL, width=320, height=220, highlightthickness=0)
        self.chart.pack(fill='both', expand=True, pady=(12, 0))
        self.chart.bind('<Configure>', lambda e: self._draw_chart(report))
        devices = self.card()
        devices.pack(fill='x', pady=(0, 14))
        top = tk.Frame(devices, bg=PANEL)
        top.pack(fill='x')
        self.label(top, '03 / DISPOSITIVOS Y EVIDENCIA', 9, ACCENT, True).pack(side='left')
        self.filter = ttk.Combobox(top, values=['Todos', *STATUSES], state='readonly', width=24)
        self.filter.set('Todos')
        self.filter.pack(side='right')
        self.filter.bind('<<ComboboxSelected>>', lambda e: self._fill_devices())
        self.table = ttk.Treeview(devices, columns=('device', 'version', 'status', 'internet', 'owner'), show='headings', height=6)
        for name, title, width in [('device', 'Dispositivo', 160), ('version', 'Producto / versión', 200),
                                   ('status', 'Evaluación', 180), ('internet', 'Internet', 75), ('owner', 'Responsable', 130)]:
            self.table.heading(name, text=title)
            self.table.column(name, width=width, minwidth=60)
        self.table.pack(fill='x', pady=(15, 8))
        for state, color in COLORS.items():
            self.table.tag_configure(state, foreground=color)
        self.detail = self.label(devices, 'Selecciona un dispositivo para ver la evidencia.', 11, MUTED, justify='left', wraplength=900)
        self.detail.pack(anchor='w', pady=8)
        self.table.bind('<<TreeviewSelect>>', self._device_detail)
        self._fill_devices()
        actions = self.card()
        actions.pack(fill='x', pady=(0, 14))
        self.label(actions, '04 / PLAN DE ACCIÓN', 9, ACCENT, True).pack(anchor='w', pady=(0, 12))
        steps = ref['pasos'] if ref else [{'titulo': 'Validar la fuente', 'detalle': 'Revisar el contenido e identificar productos afectados antes de evaluar el ambiente.', 'responsable': 'Analista SOC', 'prioridad': 'Pendiente'}]
        for i, step in enumerate(steps, 1):
            self.label(actions, f"{i:02d}  {step['titulo']}    ·    {step['responsable']} / {step['prioridad']}", 12, TEXT, True).pack(anchor='w', pady=(8, 4))
            self.label(actions, step['detalle'], 11, MUTED, wraplength=900, justify='left').pack(anchor='w', padx=(28, 0), pady=(0, 8))
        self.label(self.body, 'ALCANCE · Inventario simulado; no se inspeccionó esta PC ni la red. Una exposición potencial no confirma una intrusión.\n“Sin coincidencia” aplica únicamente a este CVE. Guardado local en historial/analisis.',
                   10, MUTED, wraplength=950, justify='left').pack(anchor='w', pady=(4, 18))
        self.root.after_idle(lambda: self.canvas.yview_moveto(0))

    def _draw_chart(self, report):
        c = self.chart
        c.delete('all')
        width = max(c.winfo_width(), 250)
        total = len(report['dispositivos'])
        for i, state in enumerate(STATUSES):
            y = 20 + i * 65
            count = report['conteos'][state]
            c.create_text(0, y, text=state, fill=MUTED, anchor='w', font=('Segoe UI', 10))
            c.create_text(width - 4, y, text=str(count), fill=TEXT, anchor='e', font=('Segoe UI', 12, 'bold'))
            c.create_rectangle(0, y + 16, width - 4, y + 28, fill=LINE, outline='')
            if count and total:
                c.create_rectangle(0, y + 16, (width - 4) * count / total, y + 28, fill=COLORS[state], outline='')

    def _fill_devices(self):
        self.table.delete(*self.table.get_children())
        selected_filter = self.filter.get()
        for i, row in enumerate(self.report['dispositivos']):
            if selected_filter != 'Todos' and row['estado'] != selected_filter:
                continue
            self.table.insert('', 'end', iid=str(i), values=(row['nombre'], f"{row['producto']} {row.get('version') or 'sin versión'}", row['estado'], 'Sí' if row.get('internet') else 'No', row['responsable']), tags=(row['estado'],))
        items = self.table.get_children()
        if items:
            self.table.selection_set(items[0])
            self._device_detail()
        else:
            self.detail.config(text='No hay dispositivos en esta categoría.')

    def _device_detail(self, event=None):
        selection = self.table.selection()
        if not selection:
            return
        row = self.report['dispositivos'][int(selection[0])]
        text = f"{row['nombre']} · {row['ip']} · {row['rol']}\nEvidencia: {row['evidencia']}"
        if row['estado'] == STATUSES[0]:
            text += f"\nCorrección histórica mínima: {row['correccion']}. Confirmar versión soportada con el fabricante."
        self.detail.config(text=text)
