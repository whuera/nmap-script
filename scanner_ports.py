#!/usr/bin/env python3
"""
Scanner de puertos con interfaz gráfica moderna.
Creado por William Huera.
"""

import glob
import json
import os
import re
import shutil
import subprocess
import threading
import tkinter as tk
import urllib.request
import urllib.error
from tkinter import scrolledtext, filedialog, messagebox
from datetime import datetime

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.widgets.scrolled import ScrolledFrame


# ─── Constante de escaneos ────────────────────────────────────────────────────
SCANS = [
    {
        "key": "rapido",
        "label": "Escaneo rápido (-F)",
        "description": "Escanea los 100 puertos más comunes",
        "args": ["-F"],
        "prefix": "rapido",
    },
    {
        "key": "completo",
        "label": "Escaneo completo (-p-)",
        "description": "Escanea los 65 535 puertos TCP",
        "args": ["-p-"],
        "prefix": "completo",
    },
    {
        "key": "servicios",
        "label": "Servicios y versiones (-sV -sC)",
        "description": "Detecta servicios, versiones y ejecuta scripts por defecto",
        "args": ["-sV", "-sC"],
        "prefix": "servicios",
    },
    {
        "key": "vulnerabilidades",
        "label": "Vulnerabilidades (--script vuln)",
        "description": "Ejecuta scripts NSE de detección de vulnerabilidades",
        "args": ["--script", "vuln"],
        "prefix": "vulnerabilidades",
    },
]


# ─── Utilidades ───────────────────────────────────────────────────────────────
def sanitize_filename(target: str) -> str:
    return re.sub(r"[^a-zA-Z0-9.-]", "_", target)


def nmap_installed() -> bool:
    return shutil.which("nmap") is not None


# ─── Aplicación principal ────────────────────────────────────────────────────
class ScannerApp(ttk.Window):
    def __init__(self):
        super().__init__(
            title="Nmap Scanner — William Huera",
            themename="darkly",
            size=(960, 720),
            resizable=(True, True),
        )
        self.place_window_center()
        self._scanning = False
        self._thread = None

        # Directorio de trabajo por defecto: el del script
        self._output_dir = os.path.dirname(os.path.abspath(__file__))

        self._build_ui()
        self._check_nmap()

    # ── Construcción de la interfaz ──────────────────────────────────────────
    def _build_ui(self):
        # Encabezado
        header = ttk.Frame(self, padding=15)
        header.pack(fill=X)
        ttk.Label(
            header,
            text="⚡  Nmap Port Scanner",
            font=("-size", 22, "-weight", "bold"),
            bootstyle="info",
        ).pack(side=LEFT)
        ttk.Label(
            header,
            text="by William Huera",
            font=("-size", 11),
            bootstyle="secondary",
        ).pack(side=RIGHT)

        ttk.Separator(self).pack(fill=X, padx=15)

        # Cuerpo principal
        body = ttk.Frame(self, padding=15)
        body.pack(fill=BOTH, expand=True)

        # ── Panel izquierdo (configuración) ──
        left = ttk.Labelframe(body, text="  Configuración  ", padding=15, bootstyle="info")
        left.pack(side=LEFT, fill=Y, padx=(0, 10))

        # Objetivo
        ttk.Label(left, text="IP o dominio:", font=("-size", 11)).pack(anchor=W, pady=(0, 4))
        self._target_var = ttk.StringVar()
        entry = ttk.Entry(left, textvariable=self._target_var, width=28, font=("-size", 12))
        entry.pack(fill=X, pady=(0, 12))
        entry.focus_set()

        # Directorio de salida
        ttk.Label(left, text="Directorio de salida:", font=("-size", 11)).pack(anchor=W, pady=(0, 4))
        dir_frame = ttk.Frame(left)
        dir_frame.pack(fill=X, pady=(0, 12))
        self._dir_var = ttk.StringVar(value=self._output_dir)
        ttk.Entry(dir_frame, textvariable=self._dir_var, font=("-size", 10)).pack(side=LEFT, fill=X, expand=True)
        ttk.Button(dir_frame, text="📂", width=3, command=self._pick_dir, bootstyle="secondary-outline").pack(
            side=RIGHT, padx=(5, 0)
        )

        # Selección de escaneos
        ttk.Label(left, text="Escaneos a ejecutar:", font=("-size", 11)).pack(anchor=W, pady=(0, 4))
        self._scan_vars: dict[str, tk.BooleanVar] = {}
        for scan in SCANS:
            var = tk.BooleanVar(value=True)
            self._scan_vars[scan["key"]] = var
            cb = ttk.Checkbutton(left, text=scan["label"], variable=var, bootstyle="info-round-toggle")
            cb.pack(anchor=W, pady=2)

        # Separador
        ttk.Separator(left).pack(fill=X, pady=(12, 10))

        # ── Sugerencia IA (n8n) ──
        ttk.Label(left, text="Sugerencia IA (n8n):", font=("-size", 11)).pack(anchor=W, pady=(0, 4))
        self._ia_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            left, text="Sugerencia IA", variable=self._ia_var,
            bootstyle="warning-round-toggle", command=self._toggle_webhook_entry,
        ).pack(anchor=W, pady=2)

        self._webhook_frame = ttk.Frame(left)
        self._webhook_frame.pack(fill=X, pady=(4, 0))
        ttk.Label(self._webhook_frame, text="Webhook URL:", font=("-size", 9)).pack(anchor=W)
        self._webhook_var = ttk.StringVar(value="https://whuera.app.n8n.cloud/webhook-test/29953877-1012-4b79-9800-52c6aa815bcf")
        self._webhook_entry = ttk.Entry(
            self._webhook_frame, textvariable=self._webhook_var, font=("-size", 9), width=28
        )
        self._webhook_entry.pack(fill=X, pady=(2, 0))
        # Ocultar inicialmente
        self._webhook_frame.pack_forget()

        # Botones
        btn_frame = ttk.Frame(left)
        btn_frame.pack(fill=X, pady=(20, 0))
        self._scan_btn = ttk.Button(
            btn_frame,
            text="▶  Iniciar Escaneo",
            command=self._start_scan,
            bootstyle="success",
            width=20,
        )
        self._scan_btn.pack(fill=X, pady=(0, 6))
        self._stop_btn = ttk.Button(
            btn_frame,
            text="■  Detener",
            command=self._stop_scan,
            bootstyle="danger-outline",
            width=20,
            state=DISABLED,
        )
        self._stop_btn.pack(fill=X, pady=(0, 6))
        self._reset_btn = ttk.Button(
            btn_frame,
            text="🔄  Nuevo Escaneo",
            command=self._reset_scan,
            bootstyle="info-outline",
            width=20,
        )
        self._reset_btn.pack(fill=X)

        # ── Panel derecho (resultados) ──
        right = ttk.Frame(body)
        right.pack(side=LEFT, fill=BOTH, expand=True)

        # Progress
        prog_frame = ttk.Frame(right)
        prog_frame.pack(fill=X, pady=(0, 8))
        self._status_label = ttk.Label(prog_frame, text="Listo", font=("-size", 11), bootstyle="info")
        self._status_label.pack(side=LEFT)
        self._progress = ttk.Progressbar(prog_frame, mode="determinate", bootstyle="info-striped")
        self._progress.pack(side=RIGHT, fill=X, expand=True, padx=(12, 0))

        # Notebook con pestañas
        self._notebook = ttk.Notebook(right, bootstyle="info")
        self._notebook.pack(fill=BOTH, expand=True)

        # Pestaña de log en vivo
        log_frame = ttk.Frame(self._notebook, padding=5)
        self._notebook.add(log_frame, text="  📋 Log  ")
        self._log_text = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            font=("Menlo", 11),
            bg="#1a1a2e",
            fg="#e0e0e0",
            insertbackground="#e0e0e0",
            selectbackground="#0f3460",
            relief=FLAT,
            state=DISABLED,
        )
        self._log_text.pack(fill=BOTH, expand=True)

        # Pestañas por escaneo
        self._result_texts: dict[str, scrolledtext.ScrolledText] = {}
        for scan in SCANS:
            frame = ttk.Frame(self._notebook, padding=5)
            self._notebook.add(frame, text=f"  {scan['prefix'].capitalize()}  ")
            txt = scrolledtext.ScrolledText(
                frame,
                wrap=tk.WORD,
                font=("Menlo", 11),
                bg="#1a1a2e",
                fg="#e0e0e0",
                insertbackground="#e0e0e0",
                selectbackground="#0f3460",
                relief=FLAT,
                state=DISABLED,
            )
            txt.pack(fill=BOTH, expand=True)
            self._result_texts[scan["key"]] = txt

        # Pestaña de reportes (visor de archivos generados)
        reports_frame = ttk.Frame(self._notebook, padding=5)
        self._notebook.add(reports_frame, text="  📄 Reportes  ")
        self._build_reports_tab(reports_frame)

        # Pestaña de Sugerencia IA
        ia_frame = ttk.Frame(self._notebook, padding=5)
        self._notebook.add(ia_frame, text="  🤖 Sugerencia IA  ")
        self._build_ia_tab(ia_frame)

        # Estado inferior
        footer = ttk.Frame(self, padding=(15, 6))
        footer.pack(fill=X, side=BOTTOM)
        self._nmap_label = ttk.Label(footer, text="", font=("-size", 10), bootstyle="secondary")
        self._nmap_label.pack(side=LEFT)

    # ── Pestaña de reportes ───────────────────────────────────────────────────
    def _build_reports_tab(self, parent: ttk.Frame):
        """Construye la pestaña de reportes con lista de archivos y visor."""
        # Panel superior: controles
        toolbar = ttk.Frame(parent)
        toolbar.pack(fill=X, pady=(0, 6))

        ttk.Button(
            toolbar, text="🔄 Actualizar lista", command=self._refresh_reports, bootstyle="info-outline"
        ).pack(side=LEFT)

        self._report_info_label = ttk.Label(
            toolbar, text="Selecciona un reporte para visualizarlo", font=("-size", 10), bootstyle="secondary"
        )
        self._report_info_label.pack(side=RIGHT)

        # Contenedor dividido
        pane = ttk.Frame(parent)
        pane.pack(fill=BOTH, expand=True)

        # Lista de archivos (izquierda)
        list_frame = ttk.Labelframe(pane, text="  Archivos  ", padding=5, bootstyle="info")
        list_frame.pack(side=LEFT, fill=Y, padx=(0, 6))

        self._report_listbox = tk.Listbox(
            list_frame,
            width=35,
            font=("Menlo", 11),
            bg="#1a1a2e",
            fg="#e0e0e0",
            selectbackground="#0f3460",
            selectforeground="#ffffff",
            relief=FLAT,
            activestyle="none",
        )
        self._report_listbox.pack(fill=BOTH, expand=True)
        self._report_listbox.bind("<<ListboxSelect>>", self._on_report_select)

        # Visor de contenido (derecha)
        viewer_frame = ttk.Labelframe(pane, text="  Contenido  ", padding=5, bootstyle="info")
        viewer_frame.pack(side=LEFT, fill=BOTH, expand=True)

        self._report_text = scrolledtext.ScrolledText(
            viewer_frame,
            wrap=tk.WORD,
            font=("Menlo", 11),
            bg="#1a1a2e",
            fg="#e0e0e0",
            insertbackground="#e0e0e0",
            selectbackground="#0f3460",
            relief=FLAT,
            state=DISABLED,
        )
        self._report_text.pack(fill=BOTH, expand=True)

        # Mapeo nombre → ruta completa
        self._report_files: list[str] = []

        # Carga inicial
        self._refresh_reports()

    def _refresh_reports(self):
        """Refresca la lista de archivos .txt generados en el directorio de salida."""
        out_dir = self._dir_var.get().strip() if hasattr(self, "_dir_var") else self._output_dir
        patterns = ["rapido_*.txt", "completo_*.txt", "servicios_*.txt", "vulnerabilidades_*.txt"]
        files: list[str] = []
        for pat in patterns:
            files.extend(glob.glob(os.path.join(out_dir, pat)))

        # Ordenar por fecha de modificación (más reciente primero)
        files.sort(key=lambda f: os.path.getmtime(f), reverse=True)
        self._report_files = files

        self._report_listbox.delete(0, END)
        for f in files:
            name = os.path.basename(f)
            mod_time = datetime.fromtimestamp(os.path.getmtime(f)).strftime("%d/%m %H:%M")
            self._report_listbox.insert(END, f"{name}  ({mod_time})")

        count = len(files)
        self._report_info_label.config(text=f"{count} reporte{'s' if count != 1 else ''} encontrado{'s' if count != 1 else ''}")

    def _on_report_select(self, event):
        """Carga el contenido del archivo seleccionado en el visor."""
        selection = self._report_listbox.curselection()
        if not selection:
            return
        idx = selection[0]
        if idx >= len(self._report_files):
            return

        filepath = self._report_files[idx]
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception as exc:
            content = f"Error al leer el archivo:\n{exc}"

        self._report_text.config(state=NORMAL)
        self._report_text.delete("1.0", END)
        self._report_text.insert("1.0", content)
        self._report_text.config(state=DISABLED)

        self._report_info_label.config(text=os.path.basename(filepath))

    # ── Pestaña de Sugerencia IA ──────────────────────────────────────────────
    def _build_ia_tab(self, parent: ttk.Frame):
        """Construye la pestaña de sugerencias IA con visor + snippets."""
        toolbar = ttk.Frame(parent)
        toolbar.pack(fill=X, pady=(0, 6))

        self._ia_send_btn = ttk.Button(
            toolbar, text="🚀 Enviar resultados a n8n",
            command=self._send_to_n8n_manual, bootstyle="warning-outline",
        )
        self._ia_send_btn.pack(side=LEFT)

        self._ia_status_label = ttk.Label(
            toolbar, text="Activa 'Sugerencia IA' para enviar automáticamente al finalizar",
            font=("-size", 10), bootstyle="secondary",
        )
        self._ia_status_label.pack(side=RIGHT)

        # PanedWindow vertical para dividir sugerencias y snippets
        paned = ttk.Panedwindow(parent, orient=tk.VERTICAL)
        paned.pack(fill=BOTH, expand=True)

        # ── Panel superior: sugerencias formateadas ──
        top_frame = ttk.Labelframe(paned, text="  📝 Sugerencias  ", padding=5, bootstyle="warning")
        self._ia_text = scrolledtext.ScrolledText(
            top_frame,
            wrap=tk.WORD,
            font=("Menlo", 11),
            bg="#1a1a2e",
            fg="#e0e0e0",
            insertbackground="#e0e0e0",
            selectbackground="#0f3460",
            relief=FLAT,
            state=DISABLED,
        )
        self._ia_text.pack(fill=BOTH, expand=True)
        # Configurar tags de colores para formato
        self._ia_text.tag_configure("header", foreground="#f0c040", font=("Menlo", 13, "bold"))
        self._ia_text.tag_configure("subheader", foreground="#56c8ff", font=("Menlo", 11, "bold"))
        self._ia_text.tag_configure("command", foreground="#50fa7b", font=("Menlo", 11))
        self._ia_text.tag_configure("warning_text", foreground="#ffb86c")
        self._ia_text.tag_configure("normal", foreground="#e0e0e0")
        paned.add(top_frame, weight=3)

        # ── Panel inferior: snippets copiables ──
        bottom_frame = ttk.Labelframe(paned, text="  📋 Comandos sugeridos (clic para copiar)  ", padding=5, bootstyle="success")
        self._snippets_container = ttk.Frame(bottom_frame)

        # Canvas + Scrollbar para scroll de snippets
        self._snippets_canvas = tk.Canvas(
            self._snippets_container, bg="#1a1a2e", highlightthickness=0, height=140
        )
        snippets_scrollbar = ttk.Scrollbar(
            self._snippets_container, orient=tk.VERTICAL, command=self._snippets_canvas.yview
        )
        self._snippets_inner = ttk.Frame(self._snippets_canvas)
        self._snippets_inner.bind(
            "<Configure>",
            lambda e: self._snippets_canvas.configure(scrollregion=self._snippets_canvas.bbox("all")),
        )
        self._snippets_canvas.create_window((0, 0), window=self._snippets_inner, anchor="nw")
        self._snippets_canvas.configure(yscrollcommand=snippets_scrollbar.set)

        self._snippets_container.pack(fill=BOTH, expand=True)
        self._snippets_canvas.pack(side=LEFT, fill=BOTH, expand=True)
        snippets_scrollbar.pack(side=RIGHT, fill=Y)

        paned.add(bottom_frame, weight=1)

    def _toggle_webhook_entry(self):
        """Muestra u oculta el campo de webhook URL."""
        if self._ia_var.get():
            self._webhook_frame.pack(fill=X, pady=(4, 0))
        else:
            self._webhook_frame.pack_forget()

    def _set_ia_text(self, content: str):
        """Escribe contenido en la pestaña de Sugerencia IA."""
        self._ia_text.config(state=NORMAL)
        self._ia_text.delete("1.0", END)
        self._ia_text.insert("1.0", content)
        self._ia_text.config(state=DISABLED)

    def _set_ia_formatted(self, formatted_text: str, commands: list[str]):
        """Escribe texto formateado y genera snippets copiables."""
        # Escribir texto formateado con colores
        self._ia_text.config(state=NORMAL)
        self._ia_text.delete("1.0", END)

        for line in formatted_text.split("\n"):
            stripped = line.strip()
            if stripped.startswith("═") or stripped.startswith("─"):
                self._ia_text.insert(END, line + "\n", "header")
            elif stripped.startswith("🤖") or stripped.startswith("📅") or stripped.startswith("🎯"):
                self._ia_text.insert(END, line + "\n", "header")
            elif stripped.startswith("##") or stripped.startswith("▶") or stripped.startswith("●"):
                self._ia_text.insert(END, line + "\n", "subheader")
            elif stripped.startswith("$") or stripped.startswith("sudo") or stripped.startswith("nmap"):
                self._ia_text.insert(END, line + "\n", "command")
            elif stripped.startswith("⚠") or stripped.startswith("[!"):
                self._ia_text.insert(END, line + "\n", "warning_text")
            else:
                self._ia_text.insert(END, line + "\n", "normal")

        self._ia_text.config(state=DISABLED)

        # Generar snippets copiables
        self._populate_snippets(commands)

    def _populate_snippets(self, commands: list[str]):
        """Crea botones de snippet para cada comando sugerido."""
        # Limpiar snippets anteriores
        for widget in self._snippets_inner.winfo_children():
            widget.destroy()

        if not commands:
            ttk.Label(
                self._snippets_inner, text="No se detectaron comandos en la respuesta.",
                font=("-size", 10), bootstyle="secondary",
            ).pack(anchor=W, padx=5, pady=5)
            return

        for i, cmd in enumerate(commands, 1):
            row = ttk.Frame(self._snippets_inner)
            row.pack(fill=X, padx=4, pady=3)

            # Etiqueta del comando con fondo oscuro
            cmd_label = tk.Label(
                row,
                text=f"  {cmd}  ",
                font=("Menlo", 11),
                bg="#16213e",
                fg="#50fa7b",
                anchor="w",
                padx=8,
                pady=4,
                relief="ridge",
                bd=1,
            )
            cmd_label.pack(side=LEFT, fill=X, expand=True)

            # Botón copiar
            copy_btn = ttk.Button(
                row,
                text="📋 Copiar",
                bootstyle="success-outline",
                width=10,
                command=lambda c=cmd: self._copy_to_clipboard(c),
            )
            copy_btn.pack(side=RIGHT, padx=(6, 0))

    def _copy_to_clipboard(self, text: str):
        """Copia el texto al portapapeles y muestra confirmación."""
        self.clipboard_clear()
        self.clipboard_append(text)
        self._ia_status_label.config(text="✔ Comando copiado al portapapeles", bootstyle="success")
        # Restaurar después de 2 segundos
        self.after(2000, lambda: self._ia_status_label.config(
            text="✔ Respuesta recibida", bootstyle="success"
        ))

    def _send_to_n8n_manual(self):
        """Envío manual: recopila todos los resultados y los envía a n8n."""
        target = self._target_var.get().strip()
        if not target:
            messagebox.showwarning("Advertencia", "Primero ingresa un objetivo y ejecuta un escaneo.")
            return

        results = {}
        for scan in SCANS:
            widget = self._result_texts.get(scan["key"])
            if widget:
                widget.config(state=NORMAL)
                text = widget.get("1.0", END).strip()
                widget.config(state=DISABLED)
                if text:
                    results[scan["key"]] = text

        if not results:
            messagebox.showinfo("Sin datos", "No hay resultados de escaneo para enviar.")
            return

        threading.Thread(
            target=self._send_to_n8n, args=(target, results), daemon=True
        ).start()

    def _send_to_n8n(self, target: str, results: dict[str, str]):
        """Envía los resultados del escaneo al webhook de n8n y muestra la respuesta."""
        webhook_url = self._webhook_var.get().strip()
        if not webhook_url:
            self.after(0, self._set_ia_text, "Error: No se configuró la URL del webhook de n8n.")
            return

        self.after(0, self._ia_status_label.config, {"text": "Enviando a n8n…", "bootstyle": "warning"})
        self.after(0, self._set_ia_text, "⏳ Enviando resultados al flujo de n8n...\n\nEsto puede tardar unos segundos.")
        self.after(0, self._ia_send_btn.config, {"state": DISABLED})

        # Navegar a la pestaña IA
        ia_tab_index = self._notebook.index(END) - 1
        self.after(0, self._notebook.select, ia_tab_index)

        payload = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "results": results,
        }

        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                raw = resp.read().decode("utf-8")

            # Parsear y formatear la respuesta
            formatted, commands = self._format_n8n_response(raw, target)
            self.after(0, self._set_ia_formatted, formatted, commands)
            self.after(0, self._ia_status_label.config, {"text": "✔ Respuesta recibida", "bootstyle": "success"})
            self.after(0, self._log, "[✓] Sugerencias IA recibidas desde n8n")

        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            err_msg = f"Error HTTP {exc.code}:\n{exc.reason}\n\n{body}"
            self.after(0, self._set_ia_text, err_msg)
            self.after(0, self._ia_status_label.config, {"text": f"✖ Error HTTP {exc.code}", "bootstyle": "danger"})
            self.after(0, self._log, f"[✖] Error al enviar a n8n: HTTP {exc.code}")

        except urllib.error.URLError as exc:
            err_msg = f"Error de conexión:\n{exc.reason}\n\nVerifica que n8n esté corriendo y la URL del webhook sea correcta."
            self.after(0, self._set_ia_text, err_msg)
            self.after(0, self._ia_status_label.config, {"text": "✖ Error de conexión", "bootstyle": "danger"})
            self.after(0, self._log, f"[✖] Error de conexión con n8n: {exc.reason}")

        except Exception as exc:
            err_msg = f"Error inesperado:\n{exc}"
            self.after(0, self._set_ia_text, err_msg)
            self.after(0, self._ia_status_label.config, {"text": "✖ Error", "bootstyle": "danger"})
            self.after(0, self._log, f"[✖] Error inesperado con n8n: {exc}")

        finally:
            self.after(0, self._ia_send_btn.config, {"state": NORMAL})

    # ── Formateo de respuesta n8n ────────────────────────────────────────────
    def _format_n8n_response(self, raw: str, target: str) -> tuple[str, list[str]]:
        """
        Parsea la respuesta de n8n y la convierte en texto legible.
        Retorna (texto_formateado, lista_de_comandos).
        """
        commands: list[str] = []
        display = ""

        # Intentar parsear como JSON
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            parsed = None

        if parsed is not None:
            # Extraer el texto principal de la respuesta
            text_content = self._extract_text_from_response(parsed)
        else:
            text_content = raw

        # Extraer comandos del texto (líneas que parecen comandos de terminal)
        commands = self._extract_commands(text_content)

        # Construir encabezado
        header = (
            f"{'═' * 55}\n"
            f"  🤖  SUGERENCIAS IA — {target}\n"
            f"  📅  {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n"
            f"{'═' * 55}\n\n"
        )

        # Limpiar markdown básico para hacerlo más legible
        cleaned = self._clean_markdown(text_content)

        display = header + cleaned

        if commands:
            display += f"\n\n{'─' * 55}\n"
            display += f"  📋  {len(commands)} comando(s) detectado(s) — ver panel inferior\n"
            display += f"{'─' * 55}\n"

        return display, commands

    def _extract_text_from_response(self, data) -> str:
        """Extrae texto legible de distintas estructuras JSON de n8n."""
        if isinstance(data, str):
            return data

        if isinstance(data, list):
            parts = []
            for item in data:
                parts.append(self._extract_text_from_response(item))
            return "\n\n".join(parts)

        if isinstance(data, dict):
            # Buscar campos comunes de respuesta
            for key in ["suggestion", "response", "output", "text", "message",
                        "data", "result", "content", "answer", "reply",
                        "recommendations", "analysis"]:
                if key in data:
                    val = data[key]
                    if isinstance(val, str):
                        return val
                    elif isinstance(val, (dict, list)):
                        return self._extract_text_from_response(val)

            # Si no se encontró un campo conocido, formatear todo el dict
            return json.dumps(data, indent=2, ensure_ascii=False)

        return str(data)

    def _extract_commands(self, text: str) -> list[str]:
        """Extrae comandos de terminal del texto de la respuesta."""
        commands: list[str] = []
        lines = text.split("\n")

        # Patrones de bloques de código
        in_code_block = False
        code_block_lines: list[str] = []

        for line in lines:
            stripped = line.strip()

            # Bloques de código markdown ```
            if stripped.startswith("```"):
                if in_code_block:
                    # Fin de bloque
                    for cl in code_block_lines:
                        cl_stripped = cl.strip()
                        if cl_stripped and not cl_stripped.startswith("#"):
                            cmd = cl_stripped.lstrip("$ ").strip()
                            if cmd and cmd not in commands:
                                commands.append(cmd)
                    code_block_lines = []
                    in_code_block = False
                else:
                    in_code_block = True
                continue

            if in_code_block:
                code_block_lines.append(line)
                continue

            # Líneas que empiezan con $ (prompt de terminal)
            if stripped.startswith("$ "):
                cmd = stripped[2:].strip()
                if cmd and cmd not in commands:
                    commands.append(cmd)
                continue

            # Detectar comandos comunes de Linux/nmap inline
            cmd_prefixes = (
                "sudo ", "nmap ", "apt ", "yum ", "dnf ", "brew ",
                "systemctl ", "service ", "iptables ", "ufw ",
                "firewall-cmd ", "netstat ", "ss ", "curl ", "wget ",
                "chmod ", "chown ", "grep ", "find ", "kill ", "pkill ",
                "docker ", "nginx ", "apache2ctl ", "openssl ",
                "ssh ", "scp ", "rsync ", "patch ", "pip ",
            )
            if stripped.startswith(cmd_prefixes) and len(stripped) < 200:
                if stripped not in commands:
                    commands.append(stripped)

        return commands

    def _clean_markdown(self, text: str) -> str:
        """Limpia formato Markdown básico para mostrar texto plano legible."""
        lines = text.split("\n")
        cleaned: list[str] = []
        in_code = False

        for line in lines:
            stripped = line.strip()

            # Bloques de código
            if stripped.startswith("```"):
                if not in_code:
                    cleaned.append("  ┌─ comando ─────────────────────────")
                    in_code = True
                else:
                    cleaned.append("  └─────────────────────────────────────")
                    in_code = False
                continue

            if in_code:
                cleaned.append(f"  │  {line}")
                continue

            # Encabezados markdown
            if stripped.startswith("### "):
                cleaned.append(f"\n  ▶ {stripped[4:]}")
            elif stripped.startswith("## "):
                cleaned.append(f"\n  ● {stripped[3:]}")
            elif stripped.startswith("# "):
                cleaned.append(f"\n{'─' * 40}\n  🎯 {stripped[2:]}\n{'─' * 40}")
            # Listas con viñetas
            elif stripped.startswith("- ") or stripped.startswith("* "):
                cleaned.append(f"    • {stripped[2:]}")
            # Listas numeradas
            elif len(stripped) > 2 and stripped[0].isdigit() and stripped[1] in (".", ")"):
                cleaned.append(f"    {stripped}")
            # Negrita **texto**
            elif "**" in stripped:
                clean_line = stripped.replace("**", "")
                cleaned.append(clean_line)
            # Código inline `comando`
            elif "`" in stripped:
                clean_line = stripped.replace("`", "")
                cleaned.append(clean_line)
            else:
                cleaned.append(line)

        return "\n".join(cleaned)

    # ── Helpers ──────────────────────────────────────────────────────────────
    def _reset_scan(self):
        """Reinicia la interfaz para un nuevo escaneo."""
        # Detener escaneo activo si lo hay
        if self._scanning:
            self._scanning = False

        # Limpiar campo de objetivo y poner foco
        self._target_var.set("")
        # Buscar el entry de target y darle foco
        for widget in self.winfo_children():
            self._focus_target_entry(widget)

        # Reiniciar barra de progreso y estado
        self._progress["value"] = 0
        self._set_status("Listo", "info")

        # Limpiar log
        self._log_text.config(state=NORMAL)
        self._log_text.delete("1.0", END)
        self._log_text.config(state=DISABLED)

        # Limpiar pestañas de resultados
        for key, widget in self._result_texts.items():
            widget.config(state=NORMAL)
            widget.delete("1.0", END)
            widget.config(state=DISABLED)

        # Limpiar pestaña IA
        self._set_ia_text("")
        self._populate_snippets([])
        self._ia_status_label.config(
            text="Activa 'Sugerencia IA' para enviar automáticamente al finalizar",
            bootstyle="secondary",
        )

        # Reactivar todos los checkboxes de escaneo
        for var in self._scan_vars.values():
            var.set(True)

        # Restaurar botones
        self._scan_btn.config(state=NORMAL)
        self._stop_btn.config(state=DISABLED)

        # Ir a la pestaña de Log
        self._notebook.select(0)

        # Refrescar reportes
        self._refresh_reports()

    def _focus_target_entry(self, widget):
        """Busca recursivamente el Entry de target y le da foco."""
        if isinstance(widget, ttk.Entry):
            try:
                if str(widget.cget("textvariable")) == str(self._target_var):
                    widget.focus_set()
                    return
            except Exception:
                pass
        for child in widget.winfo_children():
            self._focus_target_entry(child)

    def _check_nmap(self):
        if nmap_installed():
            try:
                ver = subprocess.check_output(["nmap", "--version"], text=True).splitlines()[0]
            except Exception:
                ver = "nmap instalado"
            self._nmap_label.config(text=f"✔ {ver}", bootstyle="success")
        else:
            self._nmap_label.config(text="✖ nmap no está instalado", bootstyle="danger")
            self._scan_btn.config(state=DISABLED)

    def _pick_dir(self):
        d = filedialog.askdirectory(initialdir=self._output_dir)
        if d:
            self._dir_var.set(d)
            self._output_dir = d

    def _log(self, msg: str, tag: str = ""):
        self._log_text.config(state=NORMAL)
        self._log_text.insert(END, msg + "\n", tag)
        self._log_text.see(END)
        self._log_text.config(state=DISABLED)

    def _set_result(self, key: str, content: str):
        widget = self._result_texts[key]
        widget.config(state=NORMAL)
        widget.delete("1.0", END)
        widget.insert("1.0", content)
        widget.config(state=DISABLED)

    def _set_status(self, text: str, style: str = "info"):
        self._status_label.config(text=text, bootstyle=style)

    # ── Escaneo ──────────────────────────────────────────────────────────────
    def _start_scan(self):
        target = self._target_var.get().strip()
        if not target:
            messagebox.showwarning("Advertencia", "Debes ingresar una IP o dominio.")
            return

        selected = [s for s in SCANS if self._scan_vars[s["key"]].get()]
        if not selected:
            messagebox.showwarning("Advertencia", "Selecciona al menos un tipo de escaneo.")
            return

        self._output_dir = self._dir_var.get().strip()
        if not os.path.isdir(self._output_dir):
            messagebox.showerror("Error", f"El directorio no existe:\n{self._output_dir}")
            return

        self._scanning = True
        self._scan_btn.config(state=DISABLED)
        self._stop_btn.config(state=NORMAL)
        self._progress["value"] = 0
        self._progress["maximum"] = len(selected)

        # Limpiar log
        self._log_text.config(state=NORMAL)
        self._log_text.delete("1.0", END)
        self._log_text.config(state=DISABLED)

        self._thread = threading.Thread(
            target=self._run_scans, args=(target, selected), daemon=True
        )
        self._thread.start()

    def _stop_scan(self):
        self._scanning = False
        self._set_status("Detenido por el usuario", "warning")

    def _run_scans(self, target: str, scans: list[dict]):
        sanitized = sanitize_filename(target)
        timestamp = datetime.now().strftime("%H:%M:%S")

        self.after(0, self._log, f"[{timestamp}] Objetivo: {target}")
        self.after(0, self._log, f"[{timestamp}] Directorio: {self._output_dir}")
        self.after(0, self._log, "─" * 50)

        for idx, scan in enumerate(scans, 1):
            if not self._scanning:
                break

            self.after(0, self._set_status, f"({idx}/{len(scans)}) {scan['label']}…", "info")
            self.after(0, self._log, f"\n[+] {scan['label']}…")

            output_file = os.path.join(self._output_dir, f"{scan['prefix']}_{sanitized}.txt")
            cmd = ["nmap"] + scan["args"] + [target, "-oN", output_file]

            try:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
                )

                output_lines: list[str] = []
                for line in proc.stdout:  # type: ignore[union-attr]
                    if not self._scanning:
                        proc.terminate()
                        break
                    output_lines.append(line)
                    self.after(0, self._log, line.rstrip())

                proc.wait()
                full_output = "".join(output_lines)
                self.after(0, self._set_result, scan["key"], full_output)

                if proc.returncode == 0:
                    self.after(0, self._log, f"[✓] {scan['label']} completado — {output_file}")
                else:
                    self.after(0, self._log, f"[✖] {scan['label']} finalizó con errores")

            except FileNotFoundError:
                self.after(0, self._log, "[✖] Error: nmap no encontrado")
            except Exception as exc:
                self.after(0, self._log, f"[✖] Error inesperado: {exc}")

            self.after(0, self._update_progress, idx)

        if self._scanning:
            self.after(0, self._set_status, "¡Escaneo finalizado!", "success")
            self.after(0, self._log, "\n[+] ¡Escaneo finalizado! Revisa los reportes generados.")
            self.after(100, self._refresh_reports)

            # Enviar automáticamente a n8n si el checkbox está activo
            if self._ia_var.get():
                all_results = {}
                for s in scans:
                    widget = self._result_texts.get(s["key"])
                    if widget:
                        widget.config(state=NORMAL)
                        txt = widget.get("1.0", END).strip()
                        widget.config(state=DISABLED)
                        if txt:
                            all_results[s["key"]] = txt
                if all_results:
                    self.after(0, self._log, "\n[+] Enviando resultados a n8n para sugerencias IA…")
                    threading.Thread(
                        target=self._send_to_n8n, args=(target, all_results), daemon=True
                    ).start()

        self._scanning = False
        self.after(0, self._scan_btn.config, {DISABLED: False, "state": NORMAL})
        self.after(0, self._stop_btn.config, {"state": DISABLED})

    def _update_progress(self, value: int):
        self._progress["value"] = value


# ─── Punto de entrada ────────────────────────────────────────────────────────
if __name__ == "__main__":
    if not nmap_installed():
        print("[-] Error: nmap no está instalado")
    app = ScannerApp()
    app.mainloop()
