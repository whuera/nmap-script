#!/usr/bin/env python3
"""
Scanner de puertos con interfaz gráfica moderna.
Creado por William Huera.
"""

import glob
import os
import re
import shutil
import subprocess
import threading
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
from datetime import datetime

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.scrolled import ScrolledFrame


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
        self._stop_btn.pack(fill=X)

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

    # ── Helpers ──────────────────────────────────────────────────────────────
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
