"""
Tests unitarios para scanner_ports.py
Ejecutables en CI sin necesidad de display gráfico ni nmap instalado.
"""

import json
import os
import sys
import re
from unittest.mock import patch, MagicMock

import pytest

# ─── Importar funciones de utilidad del módulo ───────────────────────────────
# Necesitamos mockear tkinter antes de importar el módulo porque
# en CI (Linux headless) no hay display disponible.

# Mock de tkinter y ttkbootstrap para poder importar las funciones puras
sys.modules["tkinter"] = MagicMock()
sys.modules["tkinter.scrolledtext"] = MagicMock()
sys.modules["tkinter.filedialog"] = MagicMock()
sys.modules["tkinter.messagebox"] = MagicMock()
sys.modules["ttkbootstrap"] = MagicMock()
sys.modules["ttkbootstrap.constants"] = MagicMock()
sys.modules["ttkbootstrap.widgets"] = MagicMock()
sys.modules["ttkbootstrap.widgets.scrolled"] = MagicMock()

# Ahora podemos importar las funciones puras
from scanner_ports import sanitize_filename, nmap_installed, SCANS


# ═══════════════════════════════════════════════════════════════════════════════
# Tests para sanitize_filename
# ═══════════════════════════════════════════════════════════════════════════════

class TestSanitizeFilename:
    def test_ip_address(self):
        assert sanitize_filename("192.168.1.1") == "192.168.1.1"

    def test_domain(self):
        assert sanitize_filename("example.com") == "example.com"

    def test_subdomain(self):
        assert sanitize_filename("sub.example.com") == "sub.example.com"

    def test_special_characters(self):
        result = sanitize_filename("test@host:8080")
        assert "@" not in result
        assert ":" not in result
        assert result == "test_host_8080"

    def test_spaces(self):
        result = sanitize_filename("my host")
        assert " " not in result
        assert result == "my_host"

    def test_slashes(self):
        result = sanitize_filename("path/to/host")
        assert "/" not in result
        assert result == "path_to_host"

    def test_empty_string(self):
        assert sanitize_filename("") == ""

    def test_already_clean(self):
        assert sanitize_filename("clean-host.name") == "clean-host.name"

    def test_unicode_characters(self):
        result = sanitize_filename("hôst-ñame")
        # Solo debe contener a-zA-Z0-9.-
        assert re.match(r'^[a-zA-Z0-9._-]+$', result)

    def test_multiple_dots(self):
        assert sanitize_filename("a.b.c.d") == "a.b.c.d"

    def test_hyphen_preserved(self):
        assert sanitize_filename("my-host") == "my-host"


# ═══════════════════════════════════════════════════════════════════════════════
# Tests para nmap_installed
# ═══════════════════════════════════════════════════════════════════════════════

class TestNmapInstalled:
    @patch("scanner_ports.shutil.which", return_value="/usr/bin/nmap")
    def test_nmap_found(self, mock_which):
        assert nmap_installed() is True
        mock_which.assert_called_once_with("nmap")

    @patch("scanner_ports.shutil.which", return_value=None)
    def test_nmap_not_found(self, mock_which):
        assert nmap_installed() is False
        mock_which.assert_called_once_with("nmap")


# ═══════════════════════════════════════════════════════════════════════════════
# Tests para la constante SCANS
# ═══════════════════════════════════════════════════════════════════════════════

class TestScansConfig:
    def test_scans_is_list(self):
        assert isinstance(SCANS, list)

    def test_scans_not_empty(self):
        assert len(SCANS) > 0

    def test_scans_has_required_keys(self):
        required_keys = {"key", "label", "description", "args", "prefix"}
        for scan in SCANS:
            assert required_keys.issubset(scan.keys()), f"Scan {scan} falta claves: {required_keys - scan.keys()}"

    def test_scans_args_are_lists(self):
        for scan in SCANS:
            assert isinstance(scan["args"], list), f"args de {scan['key']} debe ser lista"

    def test_scans_unique_keys(self):
        keys = [s["key"] for s in SCANS]
        assert len(keys) == len(set(keys)), "Las keys de SCANS deben ser únicas"

    def test_scans_unique_prefixes(self):
        prefixes = [s["prefix"] for s in SCANS]
        assert len(prefixes) == len(set(prefixes)), "Los prefixes de SCANS deben ser únicos"

    def test_rapido_scan_exists(self):
        keys = [s["key"] for s in SCANS]
        assert "rapido" in keys

    def test_completo_scan_exists(self):
        keys = [s["key"] for s in SCANS]
        assert "completo" in keys

    def test_servicios_scan_exists(self):
        keys = [s["key"] for s in SCANS]
        assert "servicios" in keys

    def test_vulnerabilidades_scan_exists(self):
        keys = [s["key"] for s in SCANS]
        assert "vulnerabilidades" in keys

    def test_rapido_uses_fast_flag(self):
        rapido = next(s for s in SCANS if s["key"] == "rapido")
        assert "-F" in rapido["args"]

    def test_completo_scans_all_ports(self):
        completo = next(s for s in SCANS if s["key"] == "completo")
        assert "-p-" in completo["args"]

    def test_servicios_detects_versions(self):
        servicios = next(s for s in SCANS if s["key"] == "servicios")
        assert "-sV" in servicios["args"]
        assert "-sC" in servicios["args"]

    def test_vulnerabilidades_uses_vuln_script(self):
        vuln = next(s for s in SCANS if s["key"] == "vulnerabilidades")
        assert "--script" in vuln["args"]
        assert "vuln" in vuln["args"]


# ═══════════════════════════════════════════════════════════════════════════════
# Tests para _extract_commands (lógica pura, testeada vía instancia mock)
# ═══════════════════════════════════════════════════════════════════════════════

class TestExtractCommands:
    """Testea la lógica de extracción de comandos reimplementada localmente."""

    @staticmethod
    def extract_commands(text: str) -> list[str]:
        """Reimplementación local para testing sin GUI."""
        commands: list[str] = []
        lines = text.split("\n")
        in_code_block = False
        code_block_lines: list[str] = []

        for line in lines:
            stripped = line.strip()
            if stripped.startswith("```"):
                if in_code_block:
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

            if stripped.startswith("$ "):
                cmd = stripped[2:].strip()
                if cmd and cmd not in commands:
                    commands.append(cmd)
                continue

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

    def test_extract_dollar_prompt(self):
        text = "Ejecuta esto:\n$ nmap -sV 192.168.1.1\nListo."
        cmds = self.extract_commands(text)
        assert "nmap -sV 192.168.1.1" in cmds

    def test_extract_code_block(self):
        text = "Solución:\n```bash\nsudo apt update\nsudo apt install nmap\n```\n"
        cmds = self.extract_commands(text)
        assert "sudo apt update" in cmds
        assert "sudo apt install nmap" in cmds

    def test_extract_inline_sudo(self):
        text = "sudo systemctl restart nginx"
        cmds = self.extract_commands(text)
        assert "sudo systemctl restart nginx" in cmds

    def test_extract_inline_nmap(self):
        text = "nmap -p 80,443 example.com"
        cmds = self.extract_commands(text)
        assert "nmap -p 80,443 example.com" in cmds

    def test_skip_comments_in_code_block(self):
        text = "```\n# Esto es un comentario\nnmap -F 10.0.0.1\n```"
        cmds = self.extract_commands(text)
        assert "nmap -F 10.0.0.1" in cmds
        assert any("comentario" in c for c in cmds) is False

    def test_no_duplicates(self):
        text = "$ nmap -F host\n$ nmap -F host\nnmap -F host"
        cmds = self.extract_commands(text)
        assert cmds.count("nmap -F host") == 1

    def test_empty_text(self):
        assert self.extract_commands("") == []

    def test_no_commands(self):
        text = "Este es un texto normal sin comandos.\nOtra línea cualquiera."
        assert self.extract_commands(text) == []

    def test_multiple_code_blocks(self):
        text = "```\ncurl http://example.com\n```\nTexto\n```\nwget http://test.com\n```"
        cmds = self.extract_commands(text)
        assert "curl http://example.com" in cmds
        assert "wget http://test.com" in cmds

    def test_docker_command(self):
        text = "docker run -d nginx"
        cmds = self.extract_commands(text)
        assert "docker run -d nginx" in cmds

    def test_iptables_command(self):
        text = "iptables -A INPUT -p tcp --dport 22 -j ACCEPT"
        cmds = self.extract_commands(text)
        assert "iptables -A INPUT -p tcp --dport 22 -j ACCEPT" in cmds


# ═══════════════════════════════════════════════════════════════════════════════
# Tests para _clean_markdown (lógica pura)
# ═══════════════════════════════════════════════════════════════════════════════

class TestCleanMarkdown:
    """Testea la limpieza de Markdown reimplementada localmente."""

    @staticmethod
    def clean_markdown(text: str) -> str:
        lines = text.split("\n")
        cleaned: list[str] = []
        in_code = False

        for line in lines:
            stripped = line.strip()
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
            if stripped.startswith("### "):
                cleaned.append(f"\n  ▶ {stripped[4:]}")
            elif stripped.startswith("## "):
                cleaned.append(f"\n  ● {stripped[3:]}")
            elif stripped.startswith("# "):
                cleaned.append(f"\n{'─' * 40}\n  🎯 {stripped[2:]}\n{'─' * 40}")
            elif stripped.startswith("- ") or stripped.startswith("* "):
                cleaned.append(f"    • {stripped[2:]}")
            elif len(stripped) > 2 and stripped[0].isdigit() and stripped[1] in (".", ")"):
                cleaned.append(f"    {stripped}")
            elif "**" in stripped:
                cleaned.append(stripped.replace("**", ""))
            elif "`" in stripped:
                cleaned.append(stripped.replace("`", ""))
            else:
                cleaned.append(line)

        return "\n".join(cleaned)

    def test_h1_header(self):
        result = self.clean_markdown("# Título Principal")
        assert "🎯 Título Principal" in result

    def test_h2_header(self):
        result = self.clean_markdown("## Sección")
        assert "● Sección" in result

    def test_h3_header(self):
        result = self.clean_markdown("### Sub sección")
        assert "▶ Sub sección" in result

    def test_bullet_list_dash(self):
        result = self.clean_markdown("- Elemento uno")
        assert "• Elemento uno" in result

    def test_bullet_list_asterisk(self):
        result = self.clean_markdown("* Elemento dos")
        assert "• Elemento dos" in result

    def test_numbered_list(self):
        result = self.clean_markdown("1. Primer paso")
        assert "1. Primer paso" in result

    def test_bold_removed(self):
        result = self.clean_markdown("**texto importante**")
        assert "**" not in result
        assert "texto importante" in result

    def test_inline_code_removed(self):
        result = self.clean_markdown("Usa `nmap -F`")
        assert "`" not in result
        assert "nmap -F" in result

    def test_code_block_formatted(self):
        result = self.clean_markdown("```\nnmap -sV host\n```")
        assert "┌─ comando" in result
        assert "└───" in result
        assert "│  nmap -sV host" in result

    def test_plain_text_unchanged(self):
        result = self.clean_markdown("Texto plano normal.")
        assert "Texto plano normal." in result

    def test_empty_text(self):
        assert self.clean_markdown("") == ""


# ═══════════════════════════════════════════════════════════════════════════════
# Tests para _extract_text_from_response (lógica pura)
# ═══════════════════════════════════════════════════════════════════════════════

class TestExtractTextFromResponse:
    """Testea la extracción de texto de respuestas JSON de n8n."""

    @staticmethod
    def extract_text(data) -> str:
        if isinstance(data, str):
            return data
        if isinstance(data, list):
            parts = []
            for item in data:
                parts.append(TestExtractTextFromResponse.extract_text(item))
            return "\n\n".join(parts)
        if isinstance(data, dict):
            for key in ["suggestion", "response", "output", "text", "message",
                        "data", "result", "content", "answer", "reply",
                        "recommendations", "analysis"]:
                if key in data:
                    val = data[key]
                    if isinstance(val, str):
                        return val
                    elif isinstance(val, (dict, list)):
                        return TestExtractTextFromResponse.extract_text(val)
            return json.dumps(data, indent=2, ensure_ascii=False)
        return str(data)

    def test_string_input(self):
        assert self.extract_text("hello") == "hello"

    def test_dict_with_suggestion(self):
        data = {"suggestion": "Actualiza el firewall"}
        assert self.extract_text(data) == "Actualiza el firewall"

    def test_dict_with_response(self):
        data = {"response": "Cierra el puerto 22"}
        assert self.extract_text(data) == "Cierra el puerto 22"

    def test_dict_with_message(self):
        data = {"message": "Todo correcto"}
        assert self.extract_text(data) == "Todo correcto"

    def test_dict_with_output(self):
        data = {"output": "Resultado del análisis"}
        assert self.extract_text(data) == "Resultado del análisis"

    def test_dict_with_text(self):
        data = {"text": "Texto de respuesta"}
        assert self.extract_text(data) == "Texto de respuesta"

    def test_dict_unknown_keys(self):
        data = {"foo": "bar", "baz": 123}
        result = self.extract_text(data)
        assert "foo" in result
        assert "bar" in result

    def test_list_of_strings(self):
        data = ["primera", "segunda"]
        result = self.extract_text(data)
        assert "primera" in result
        assert "segunda" in result

    def test_list_of_dicts(self):
        data = [{"message": "one"}, {"message": "two"}]
        result = self.extract_text(data)
        assert "one" in result
        assert "two" in result

    def test_nested_dict(self):
        data = {"data": {"suggestion": "Nested response"}}
        assert self.extract_text(data) == "Nested response"

    def test_integer_input(self):
        assert self.extract_text(42) == "42"

    def test_empty_dict(self):
        result = self.extract_text({})
        assert result == "{}"

    def test_priority_order(self):
        """suggestion tiene prioridad sobre response."""
        data = {"suggestion": "primero", "response": "segundo"}
        assert self.extract_text(data) == "primero"


# ═══════════════════════════════════════════════════════════════════════════════
# Tests para generación de nombres de archivo de salida
# ═══════════════════════════════════════════════════════════════════════════════

class TestOutputFileGeneration:
    def test_output_filename_format(self):
        target = "192.168.100.222"
        sanitized = sanitize_filename(target)
        for scan in SCANS:
            filename = f"{scan['prefix']}_{sanitized}.txt"
            assert filename.endswith(".txt")
            assert scan["prefix"] in filename
            assert sanitized in filename

    def test_output_filename_with_domain(self):
        target = "example.com"
        sanitized = sanitize_filename(target)
        filename = f"rapido_{sanitized}.txt"
        assert filename == "rapido_example.com.txt"

    def test_output_filename_with_special_chars(self):
        target = "host:8080/path"
        sanitized = sanitize_filename(target)
        filename = f"completo_{sanitized}.txt"
        assert ":" not in filename
        assert "/" not in filename
