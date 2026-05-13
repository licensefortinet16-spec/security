#!/usr/bin/env python3
import base64
import csv
import hashlib
import html
import hmac
import io
import json
import os
import subprocess
import secrets
import time
import threading
import tomllib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse
import re


ROOT = Path(os.environ.get("SECURITY_ROOT", "/opt/security/security"))
PUBLIC_HOST = os.environ.get("SECURITY_PUBLIC_HOST", "200.160.19.14")
BIND = os.environ.get("SECURITY_STATUS_BIND", PUBLIC_HOST)
PORT = int(os.environ.get("SECURITY_STATUS_PORT", "8090"))
AUTH_USER = os.environ.get("SECURITY_STATUS_USERNAME", "")
AUTH_PASSWORD = os.environ.get("SECURITY_STATUS_PASSWORD", "")
AUTH_PASSWORD_FILE = os.environ.get("SECURITY_STATUS_PASSWORD_FILE", "")
AUTH_TOKEN = os.environ.get("SECURITY_STATUS_TOKEN", "")
AUTH_TOKEN_FILE = os.environ.get("SECURITY_STATUS_TOKEN_FILE", "")
SESSION_SECRET_FILE = os.environ.get("SECURITY_STATUS_SESSION_FILE", "/etc/container-security-monitor/status-session.secret")
SESSION_TTL_SECONDS = int(os.environ.get("SECURITY_STATUS_SESSION_TTL_SECONDS", "43200"))
SCAN_SCRIPT = os.environ.get("SECURITY_SCAN_SCRIPT", str(ROOT / "scanner" / "scan_remote_hosts.sh"))
SCAN_STATE_FILE = Path(os.environ.get("SECURITY_SCAN_STATE_FILE", str(ROOT / "output" / "scan" / "manual_scan_state.json")))
SCAN_SCHEDULE_FILE = Path(os.environ.get("SECURITY_SCAN_SCHEDULE_FILE", str(ROOT / "config" / "scan_schedule.json")))
CODE_SCAN_CONFIG_FILE = Path(os.environ.get("SECURITY_CODE_SCAN_CONFIG_FILE", str(ROOT / "config" / "code_scan.toml")))
SCAN_TIMER_NAME = os.environ.get("SECURITY_SCAN_TIMER_NAME", "container-security-scan.timer")
SCAN_SERVICE_NAME = os.environ.get("SECURITY_SCAN_SERVICE_NAME", "container-security-scan.service")
SCAN_TIMER_PATH = Path(os.environ.get("SECURITY_SCAN_TIMER_PATH", f"/etc/systemd/system/{SCAN_TIMER_NAME}"))
REPO_SCAN_TIMER_PATH = ROOT / "systemd" / SCAN_TIMER_NAME
SCAN_LOCK = threading.Lock()


def load_auth_token():
    if AUTH_TOKEN:
        return AUTH_TOKEN
    if AUTH_TOKEN_FILE:
        try:
            return Path(AUTH_TOKEN_FILE).read_text(encoding="utf-8").strip()
        except OSError:
            return ""
    return ""


AUTH_TOKEN_VALUE = load_auth_token()


def load_auth_password():
    if AUTH_PASSWORD:
        return AUTH_PASSWORD
    if AUTH_PASSWORD_FILE:
        try:
            return Path(AUTH_PASSWORD_FILE).read_text(encoding="utf-8").strip()
        except OSError:
            return ""
    return ""


AUTH_PASSWORD_VALUE = load_auth_password()


def load_session_secret():
    try:
        return Path(SESSION_SECRET_FILE).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


SESSION_SECRET = load_session_secret()


def read_json(path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def esc(value):
    return html.escape(str(value if value is not None else ""))


def latest_file(directory, pattern):
    files = sorted(directory.glob(pattern))
    return files[-1] if files else None


def set_manual_scan_state(state, **extra):
    SCAN_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "state": state,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    payload.update(extra)
    SCAN_STATE_FILE.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def manual_scan_state():
    return read_json(SCAN_STATE_FILE, {})


WEEKDAYS = {
    "mon": "Mon",
    "tue": "Tue",
    "wed": "Wed",
    "thu": "Thu",
    "fri": "Fri",
    "sat": "Sat",
    "sun": "Sun",
}

WEEKDAY_LABELS = {
    "mon": "Segunda",
    "tue": "Terca",
    "wed": "Quarta",
    "thu": "Quinta",
    "fri": "Sexta",
    "sat": "Sabado",
    "sun": "Domingo",
}


def default_scan_schedule():
    return {
        "enabled": True,
        "frequency": "weekly",
        "weekday": "sun",
        "hour": 2,
        "minute": 0,
        "randomized_delay_minutes": 15,
        "on_calendar": "Sun *-*-* 02:00:00",
        "updated_at": None,
        "last_apply_status": "default",
        "last_apply_message": "Timer semanal padrao.",
    }


def load_scan_schedule():
    data = read_json(SCAN_SCHEDULE_FILE, {}) or {}
    schedule = default_scan_schedule()
    schedule.update({key: value for key, value in data.items() if value is not None})
    normalized, errors = normalize_scan_schedule(schedule)
    if errors:
        return default_scan_schedule()
    normalized.update({key: schedule.get(key) for key in ("updated_at", "last_apply_status", "last_apply_message") if schedule.get(key) is not None})
    return normalized


def normalize_scan_schedule(data):
    errors = []
    enabled = str(data.get("enabled", "true")).lower() in {"1", "true", "yes", "on"}
    frequency = str(data.get("frequency") or "daily").lower()
    if frequency not in {"daily", "weekly"}:
        errors.append("Frequencia invalida.")
        frequency = "daily"
    weekday = str(data.get("weekday") or "sun").lower()
    if weekday not in WEEKDAYS:
        errors.append("Dia da semana invalido.")
        weekday = "sun"
    try:
        hour = int(data.get("hour"))
    except (TypeError, ValueError):
        hour = -1
    try:
        minute = int(data.get("minute"))
    except (TypeError, ValueError):
        minute = -1
    try:
        randomized_delay_minutes = int(data.get("randomized_delay_minutes", 0) or 0)
    except (TypeError, ValueError):
        randomized_delay_minutes = 0
    if hour < 0 or hour > 23:
        errors.append("Hora deve ficar entre 0 e 23.")
        hour = 0
    if minute < 0 or minute > 59:
        errors.append("Minuto deve ficar entre 0 e 59.")
        minute = 0
    if randomized_delay_minutes < 0 or randomized_delay_minutes > 120:
        errors.append("Atraso aleatorio deve ficar entre 0 e 120 minutos.")
        randomized_delay_minutes = 0
    on_calendar = build_on_calendar(frequency, weekday, hour, minute)
    return {
        "enabled": enabled,
        "frequency": frequency,
        "weekday": weekday,
        "hour": hour,
        "minute": minute,
        "randomized_delay_minutes": randomized_delay_minutes,
        "on_calendar": on_calendar,
    }, errors


def build_on_calendar(frequency, weekday, hour, minute):
    clock = f"{hour:02d}:{minute:02d}:00"
    if frequency == "weekly":
        return f"{WEEKDAYS.get(weekday, 'Sun')} *-*-* {clock}"
    return f"*-*-* {clock}"


def schedule_label(schedule):
    if not schedule.get("enabled", True):
        return "desativado"
    hour = int(schedule.get("hour") or 0)
    minute = int(schedule.get("minute") or 0)
    clock = f"{hour:02d}:{minute:02d}"
    if schedule.get("frequency") == "weekly":
        return f"{WEEKDAY_LABELS.get(schedule.get('weekday'), 'Domingo')} as {clock}"
    return f"todos os dias as {clock}"


def write_scan_timer(schedule):
    timer_text = render_scan_timer_unit(schedule)
    REPO_SCAN_TIMER_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPO_SCAN_TIMER_PATH.write_text(timer_text, encoding="utf-8")
    SCAN_TIMER_PATH.write_text(timer_text, encoding="utf-8")
    subprocess.run(["systemctl", "daemon-reload"], check=True, text=True, capture_output=True)
    if schedule.get("enabled", True):
        subprocess.run(["systemctl", "enable", "--now", SCAN_TIMER_NAME], check=True, text=True, capture_output=True)
        subprocess.run(["systemctl", "restart", SCAN_TIMER_NAME], check=True, text=True, capture_output=True)
    else:
        subprocess.run(["systemctl", "disable", "--now", SCAN_TIMER_NAME], check=False, text=True, capture_output=True)


def render_scan_timer_unit(schedule):
    randomized = int(schedule.get("randomized_delay_minutes") or 0)
    return f"""[Unit]
Description=Container Security Monitor scheduled scan

[Timer]
OnCalendar={schedule.get('on_calendar')}
Persistent=true
RandomizedDelaySec={randomized}m
Unit={SCAN_SERVICE_NAME}

[Install]
WantedBy=timers.target
"""


def save_scan_schedule(schedule, status, message):
    payload = dict(schedule)
    payload["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    payload["last_apply_status"] = status
    payload["last_apply_message"] = message
    SCAN_SCHEDULE_FILE.parent.mkdir(parents=True, exist_ok=True)
    SCAN_SCHEDULE_FILE.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return payload


DEFAULT_CODE_EXCLUDE_DIRS = [
    ".git",
    ".cache",
    "node_modules",
    "vendor",
    "tmp",
    "logs",
    "log",
    "backup",
    "backups",
    "_sem-uso",
    "site_old",
    "old",
]


def read_toml(path):
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def parse_exclude_dirs(raw):
    values = []
    for item in re.split(r"[,\n]", str(raw or "")):
        value = item.strip().strip("/")
        if value and "/" not in value and value not in {".", ".."} and value not in values:
            values.append(value)
    return values or list(DEFAULT_CODE_EXCLUDE_DIRS)


def load_code_scan_config():
    data = read_toml(CODE_SCAN_CONFIG_FILE)
    scan = data.get("scan", {}) if isinstance(data, dict) else {}
    return {"exclude_dirs": parse_exclude_dirs("\n".join(scan.get("exclude_dirs", DEFAULT_CODE_EXCLUDE_DIRS)))}


def toml_string_list(values):
    rows = ["["]
    for value in values:
        rows.append(f'  {json.dumps(str(value))},')
    rows.append("]")
    return "\n".join(rows)


def save_code_scan_config(config):
    exclude_dirs = parse_exclude_dirs("\n".join(config.get("exclude_dirs", [])))
    CODE_SCAN_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CODE_SCAN_CONFIG_FILE.write_text(f"[scan]\nexclude_dirs = {toml_string_list(exclude_dirs)}\n", encoding="utf-8")


def latest_scan_log_lines(limit=30):
    path = latest_file(ROOT / "output" / "logs", "scan_*.log")
    if not path:
        return "Nenhum log de scan encontrado."
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]
    except OSError as exc:
        return str(exc)
    body = "\n".join(lines) if lines else "Log vazio."
    return f"{path.name}\n{body}"


def render_code_scan_config_panel(config, query):
    notice = ""
    if query.get("code_scan", [""])[0] == "saved":
        notice = '<div class="empty">Configuracao SAST salva.</div>'
    elif query.get("code_scan", [""])[0] == "failed":
        notice = '<div class="empty">Nao foi possivel salvar a configuracao SAST.</div>'
    values = "\n".join(config.get("exclude_dirs") or [])
    content = (
        f"{notice}"
        '<form method="post" action="/settings/code-scan">'
        '<div class="table-tools">'
        '<label>Diretorios excluidos'
        f'<textarea name="exclude_dirs" rows="8">{esc(values)}</textarea>'
        '</label>'
        '<button class="action primary" type="submit">Salvar SAST</button>'
        '</div>'
        '</form>'
    )
    return section(
        "SAST",
        "Diretorios ignorados na copia remota, no Trivy secret/misconfig, no Semgrep e no fallback PHP.",
        content,
    )


def render_latest_scan_log_panel():
    return section(
        "Ultimo log",
        "Final do log mais recente em output/logs.",
        f'<pre class="empty" style="white-space: pre-wrap; overflow-x: auto;">{esc(latest_scan_log_lines())}</pre>'
    )


def timer_status_lines():
    commands = [
        ["systemctl", "is-active", SCAN_TIMER_NAME],
        ["systemctl", "list-timers", "--all", "--no-pager", SCAN_TIMER_NAME],
    ]
    lines = []
    for command in commands:
        try:
            result = subprocess.run(command, text=True, capture_output=True, timeout=8, check=False)
            output = (result.stdout or result.stderr or "").strip()
            if output:
                lines.extend(output.splitlines())
        except Exception as exc:
            lines.append(str(exc))
    return lines


class Handler(BaseHTTPRequestHandler):
    server_version = "ContainerSecurityStatus/0.1"

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if path == "/health":
            self.json({"status": "ok"})
        elif path == "/login":
            error, next_path = self.login_params()
            self.html(render_login(error, next_path))
        elif path == "/logout":
            self.logout()
        elif not self.authorized():
            self.redirect_to_login(path)
        elif path == "/":
            self.html(render_dashboard())
        elif path == "/api/status":
            self.json(status_payload())
        elif path == "/metrics":
            self.file(ROOT / "output" / "metrics" / "container_security_latest.prom", "text/plain; charset=utf-8")
        elif path == "/reports/executive":
            self.html(render_report_page("gerencial", "executive", "executive_report_latest.html", query=query))
        elif path == "/reports/executive.pdf":
            self.file(ROOT / "output" / "reports" / "executive_report_latest.pdf", "application/pdf")
        elif path == "/reports/technical":
            self.html(render_report_page("tecnico", "technical", "technical_report_latest.html", query=query))
        elif path == "/reports/code":
            self.html(render_code_page(query=query))
        elif path == "/reports/code/finding":
            self.html(render_code_finding_page(query=query))
        elif path == "/reports/code.csv":
            self.data(render_code_csv().encode("utf-8"), "text/csv; charset=utf-8", "code_findings_latest.csv")
        elif path == "/reports/code.pdf":
            self.data(render_code_pdf(), "application/pdf", "code_findings_latest.pdf")
        elif path == "/settings":
            self.html(render_settings_page(query=query))
        elif path == "/scan/manual":
            self.send_error(405)
        elif path.startswith("/reports/technical/containers/"):
            slug = path.rsplit("/", 1)[-1]
            if not re.fullmatch(r"[a-z0-9-]+", slug or ""):
                self.send_error(400)
                return
            self.html(render_container_report_page(slug))
        else:
            self.send_error(404)

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/login":
            self.handle_login()
        elif path == "/scan/manual":
            self.handle_manual_scan()
        elif path == "/settings/schedule":
            self.handle_schedule_update()
        elif path == "/settings/code-scan":
            self.handle_code_scan_update()
        else:
            self.send_error(405)

    def html(self, content, status=200):
        data = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.security_headers()
        self.end_headers()
        self.wfile.write(data)

    def json(self, payload, status=200):
        data = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.security_headers()
        self.end_headers()
        self.wfile.write(data)

    def data(self, data, content_type, filename=None, status=200):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.security_headers()
        self.end_headers()
        self.wfile.write(data)

    def file(self, path, content_type):
        if not path.exists():
            self.send_error(404)
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.security_headers()
        self.end_headers()
        self.wfile.write(data)

    def send_error(self, code, message=None, explain=None):
        friendly = {
            400: ("Requisição inválida", "O endereço informado não pôde ser processado."),
            401: ("Acesso não autenticado", "Entre novamente para continuar."),
            403: ("Acesso negado", "Sua sessão não tem permissão para este recurso."),
            404: ("Página não encontrada", "O caminho solicitado não existe neste painel."),
            405: ("Método não permitido", "Este recurso não aceita a operação enviada."),
        }
        if code in friendly:
            title, detail = friendly[code]
            self.html(
                render_error_page(
                    code=code,
                    title=title,
                    detail=detail if message is None else str(message),
                ),
                status=code,
            )
            return
        super().send_error(code, message=message, explain=explain)

    def security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("X-Permitted-Cross-Domain-Policies", "none")

    def authorized(self):
        if self.valid_session():
            return True
        if AUTH_USER and AUTH_PASSWORD_VALUE:
            header = self.headers.get("Authorization", "")
            prefix = "Basic "
            if not header.startswith(prefix):
                return False
            try:
                decoded = base64.b64decode(header[len(prefix):]).decode("utf-8")
            except Exception:
                return False
            user, sep, password = decoded.partition(":")
            return bool(sep) and secrets.compare_digest(user, AUTH_USER) and secrets.compare_digest(password, AUTH_PASSWORD_VALUE)

        if AUTH_TOKEN_VALUE:
            header = self.headers.get("Authorization", "")
            token = header.removeprefix("Bearer ").strip() if header.startswith("Bearer ") else ""
            return secrets.compare_digest(token, AUTH_TOKEN_VALUE)

        return True

    def valid_session(self):
        cookie = self.headers.get("Cookie", "")
        if not cookie or not SESSION_SECRET:
            return False
        session_value = None
        for part in cookie.split(";"):
            name, sep, value = part.strip().partition("=")
            if name == "csm_session" and sep:
                session_value = value
                break
        if not session_value:
            return False
        try:
            payload_b64, sig = session_value.split(".", 1)
            payload = base64.urlsafe_b64decode(pad_b64(payload_b64)).decode("utf-8")
            username, expiry_text = payload.rsplit(":", 1)
            expiry = int(expiry_text)
        except Exception:
            return False
        if expiry < int(time.time()):
            return False
        expected = sign_session_payload(payload)
        return secrets.compare_digest(expected, sig)

    def handle_login(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        form = parse_qs(raw, keep_blank_values=True)
        username = form.get("username", [""])[0].strip()
        password = form.get("password", [""])[0]
        next_path = form.get("next", ["/"])[0] or "/"
        if not next_path.startswith("/"):
            next_path = "/"

        if self.login_valid(username, password):
            self.send_response(302)
            self.send_header("Location", next_path)
            self.send_header("Set-Cookie", build_session_cookie(username))
            self.security_headers()
            self.end_headers()
            return

        self.html(render_login("Credenciais invalidas.", next_path), status=401)

    def login_valid(self, username, password):
        if AUTH_USER and AUTH_PASSWORD_VALUE:
            return secrets.compare_digest(username, AUTH_USER) and secrets.compare_digest(password, AUTH_PASSWORD_VALUE)
        if AUTH_TOKEN_VALUE:
            return secrets.compare_digest(password, AUTH_TOKEN_VALUE)
        return False

    def login_params(self):
        query = parse_qs(urlparse(self.path).query)
        return query.get("error", [""])[0], query.get("next", ["/"])[0] or "/"

    def redirect_to_login(self, next_path):
        if next_path.startswith("/api/") or next_path == "/metrics":
            self.unauthorized_api()
            return
        location = "/login?" + urlencode({"next": next_path or "/"})
        self.send_response(302)
        self.send_header("Location", location)
        self.security_headers()
        self.end_headers()

    def unauthorized_api(self):
        data = b"unauthorized\n"
        self.send_response(401)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if AUTH_USER and AUTH_PASSWORD_VALUE:
            self.send_header("WWW-Authenticate", 'Basic realm="Container Security Monitor"')
        self.security_headers()
        self.end_headers()
        self.wfile.write(data)

    def logout(self):
        self.send_response(302)
        self.send_header("Location", "/login")
        self.send_header("Set-Cookie", "csm_session=deleted; Path=/; Max-Age=0; HttpOnly; SameSite=Strict")
        self.security_headers()
        self.end_headers()

    def read_form(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        return parse_qs(raw, keep_blank_values=True)

    def handle_schedule_update(self):
        if not self.authorized():
            self.redirect_to_login("/settings")
            return
        form = self.read_form()
        raw = {
            "enabled": form.get("enabled", [""])[0] == "on",
            "frequency": form.get("frequency", ["daily"])[0],
            "weekday": form.get("weekday", ["sun"])[0],
            "hour": form.get("hour", ["0"])[0],
            "minute": form.get("minute", ["0"])[0],
            "randomized_delay_minutes": form.get("randomized_delay_minutes", ["0"])[0],
        }
        schedule, errors = normalize_scan_schedule(raw)
        if errors:
            save_scan_schedule({**schedule, "enabled": raw["enabled"]}, "failed", "; ".join(errors))
            self.send_response(302)
            self.send_header("Location", "/settings?schedule=invalid")
            self.security_headers()
            self.end_headers()
            return
        try:
            write_scan_timer(schedule)
            save_scan_schedule(schedule, "success", f"Agenda aplicada: {schedule_label(schedule)}.")
            location = "/settings?schedule=saved"
        except Exception as exc:
            save_scan_schedule(schedule, "failed", str(exc))
            location = "/settings?schedule=failed"
        self.send_response(302)
        self.send_header("Location", location)
        self.security_headers()
        self.end_headers()

    def handle_code_scan_update(self):
        if not self.authorized():
            self.redirect_to_login("/settings")
            return
        form = self.read_form()
        exclude_dirs = parse_exclude_dirs(form.get("exclude_dirs", [""])[0])
        try:
            save_code_scan_config({"exclude_dirs": exclude_dirs})
            location = "/settings?code_scan=saved"
        except Exception:
            location = "/settings?code_scan=failed"
        self.send_response(302)
        self.send_header("Location", location)
        self.security_headers()
        self.end_headers()

    def handle_manual_scan(self):
        if not self.authorized():
            self.redirect_to_login("/reports/technical")
            return
        if not SCAN_LOCK.acquire(blocking=False):
            set_manual_scan_state("running", started_at=manual_scan_state().get("started_at"), note="scan already running")
            self.send_response(302)
            self.send_header("Location", "/reports/technical?scan=busy")
            self.security_headers()
            self.end_headers()
            return

        def worker():
            started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            set_manual_scan_state("running", started_at=started_at, script=SCAN_SCRIPT)
            try:
                result = subprocess.run(
                    [SCAN_SCRIPT],
                    cwd=str(ROOT),
                    env={**os.environ, "SECURITY_ROOT": str(ROOT)},
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                state = "success" if result.returncode == 0 else "partial_success"
                set_manual_scan_state(state, started_at=started_at, finished_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), exit_code=result.returncode, script=SCAN_SCRIPT)
            except Exception as exc:
                set_manual_scan_state("failed", started_at=started_at, finished_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), error=str(exc), script=SCAN_SCRIPT)
            finally:
                SCAN_LOCK.release()

        threading.Thread(target=worker, daemon=True).start()
        self.send_response(302)
        self.send_header("Location", "/reports/technical?scan=started")
        self.security_headers()
        self.end_headers()

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))


def pad_b64(value):
    return value + "=" * (-len(value) % 4)


def sign_session_payload(payload):
    if not SESSION_SECRET:
        return ""
    return hmac.new(SESSION_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def build_session_cookie(username):
    expiry = int(time.time()) + SESSION_TTL_SECONDS
    payload = f"{username}:{expiry}"
    payload_b64 = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")
    signature = sign_session_payload(payload)
    return f"csm_session={payload_b64}.{signature}; Path=/; HttpOnly; SameSite=Strict"


def status_payload():
    risk = read_json(ROOT / "output" / "history" / "risk_scores_latest.json", {})
    inventory_path = latest_file(ROOT / "output" / "inventory", "inventory_*.json")
    inventory = read_json(inventory_path, {}) if inventory_path else {}
    metrics_path = latest_file(ROOT / "output" / "metrics", "metrics_summary_*.json")
    metrics = read_json(metrics_path, {}) if metrics_path else {}
    dtrack_path = latest_file(ROOT / "output" / "dtrack", "dtrack_upload_*.json")
    dtrack = read_json(dtrack_path, {}) if dtrack_path else {}
    dtrack_analysis_path = latest_file(ROOT / "output" / "dtrack", "dtrack_analysis_*.json")
    dtrack_analysis = read_json(dtrack_analysis_path, {}) if dtrack_analysis_path else {}
    trivy_path = latest_file(ROOT / "output" / "trivy", "trivy_summary_*.json")
    trivy = read_json(trivy_path, {}) if trivy_path else {}
    code_path = ROOT / "output" / "code" / "code_summary_latest.json"
    if not code_path.exists():
        code_path = latest_file(ROOT / "output" / "code", "code_summary_*.json")
    code = read_json(code_path, {}) if code_path else {}
    alerts_path = latest_file(ROOT / "output" / "alerts", "alerts_*.json")
    alerts = read_json(alerts_path, {}) if alerts_path else {}

    scores = risk.get("scores", [])
    vulnerabilities_by_image = load_trivy_vulnerabilities(trivy)
    vulnerability_rows = build_vulnerability_rows(scores, vulnerabilities_by_image)
    vulnerability_container_summary = build_vulnerability_container_summary(scores, vulnerabilities_by_image)
    score_factor_rows = build_score_factor_rows(scores)
    history_comparison = build_history_comparison(ROOT, risk)
    return {
        "run_id": risk.get("run_id") or inventory.get("run_id"),
        "inventory_status": inventory.get("status"),
        "summary": inventory.get("summary", {}),
        "vulnerability_summary": risk.get("vulnerability_summary", {}),
        "context_summary": risk.get("context_summary", []),
        "trivy": {
            "images_total": trivy.get("images_total"),
            "success": trivy.get("success"),
            "failed": trivy.get("failed"),
        },
        "dependency_track": {
            "status": dtrack.get("status"),
            "configured": dtrack.get("configured"),
            "uploaded": dtrack.get("uploaded"),
            "failed": dtrack.get("failed"),
            "analysis_status": dtrack_analysis.get("status"),
            "analysis_totals": dtrack_analysis.get("totals", {}),
            "source_note": dtrack_analysis.get("source_note"),
        },
        "code": code,
        "alerts": {
            "status": alerts.get("status"),
            "totals": alerts.get("totals", {}),
            "active_rules": alerts.get("alerts", []),
        },
        "metrics": metrics,
        "top_risks": compact_scores(scores[:10]),
        "vulnerability_rows": vulnerability_rows[:200],
        "vulnerability_container_summary": vulnerability_container_summary[:20],
        "score_factor_rows": score_factor_rows[:300],
        "history_comparison": history_comparison,
    }


def compact_scores(scores):
    rows = []
    for item in scores:
        rows.append({
            "score": item.get("score"),
            "classification": item.get("classification"),
            "context": item.get("context"),
            "host_name": item.get("host_name"),
            "container_name": item.get("container_name"),
            "image": item.get("image"),
            "findings": item.get("findings"),
        })
    return rows


def build_score_factor_rows(scores):
    rows = []
    for item in scores or []:
        key = f"{item.get('context') or item.get('docker_context') or 'sem contexto'}|{item.get('container_name') or 'sem container'}|{item.get('image') or 'sem imagem'}"
        for factor in item.get("factors") or []:
            rows.append({
                "container_key": key,
                "host_name": item.get("host_name"),
                "context": item.get("context") or item.get("docker_context"),
                "container_name": item.get("container_name"),
                "image": item.get("image"),
                "score": item.get("score"),
                "classification": item.get("classification"),
                "type": factor.get("type"),
                "severity": factor.get("severity"),
                "points": factor.get("points"),
                "evidence": factor.get("evidence"),
            })
    rows.sort(key=lambda row: (
        -(int(row.get("score") or 0)),
        row.get("context") or "",
        row.get("container_name") or "",
        -(int(row.get("points") or 0)),
        row.get("type") or "",
    ))
    return rows


def build_history_comparison(root, current):
    current_run = current.get("run_id")
    history_dir = root / "output" / "history"
    candidates = []
    for path in sorted(history_dir.glob("risk_scores_*.json")):
        if path.name == "risk_scores_latest.json":
            continue
        data = read_json(path, {})
        if not data or data.get("run_id") == current_run:
            continue
        candidates.append(data)
    previous = candidates[-1] if candidates else {}

    def summarize(data):
        scores = data.get("scores") or []
        vuln = data.get("vulnerability_summary") or {}
        sev = vuln.get("severity_counts") or {}
        return {
            "run_id": data.get("run_id"),
            "total": int(vuln.get("total") or 0),
            "critical": int(sev.get("CRITICAL") or 0),
            "high": int(sev.get("HIGH") or 0),
            "containers": len(scores),
            "max_score": max([int(item.get("score") or 0) for item in scores] or [0]),
        }

    now = summarize(current)
    prev = summarize(previous) if previous else {}
    deltas = {}
    for key in ("total", "critical", "high", "containers", "max_score"):
        deltas[key] = now.get(key, 0) - prev.get(key, 0) if prev else 0
    return {
        "current": now,
        "previous": prev,
        "deltas": deltas,
    }


def load_trivy_vulnerabilities(trivy_summary):
    by_image = {}
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    for result in (trivy_summary or {}).get("results", []) or []:
        if result.get("status") != "success":
            continue
        image = result.get("image")
        output = result.get("vulnerability_output")
        if not image or not output:
            continue
        path = Path(output)
        if not path.exists():
            continue
        data = read_json(path, {})
        rows = []
        for trivy_result in data.get("Results", []) or []:
            for vuln in trivy_result.get("Vulnerabilities", []) or []:
                severity = vuln.get("Severity") or "UNKNOWN"
                rows.append({
                    "image": image,
                    "severity": severity,
                    "id": vuln.get("VulnerabilityID") or "unknown",
                    "package": vuln.get("PkgName") or "",
                    "installed_version": vuln.get("InstalledVersion") or "",
                    "fixed_version": vuln.get("FixedVersion") or "",
                    "title": vuln.get("Title") or (vuln.get("Description") or "")[:140],
                    "remediation": recommended_vulnerability_action(vuln),
                })
        rows.sort(key=lambda row: (
            severity_order.get(row.get("severity"), 9),
            0 if row.get("fixed_version") else 1,
            row.get("id") or "",
            row.get("package") or "",
        ))
        by_image[image] = rows
    return by_image


def recommended_vulnerability_action(vuln):
    fixed = vuln.get("FixedVersion")
    package = vuln.get("PkgName") or "pacote afetado"
    severity = vuln.get("Severity") or "UNKNOWN"
    if fixed:
        return f"Atualizar {package} para {fixed} ou usar imagem base que ja contenha essa correcao."
    if severity in {"CRITICAL", "HIGH"}:
        return "Sem versao corrigida informada pelo Trivy; avaliar mitigacao, troca de imagem/base ou compensacao de risco."
    return "Monitorar e atualizar a imagem quando houver versao corrigida."


def build_image_container_index(scores):
    by_image = {}
    for item in scores or []:
        image = item.get("image")
        if not image:
            continue
        by_image.setdefault(image, []).append({
            "host_name": item.get("host_name"),
            "context": item.get("context") or item.get("docker_context"),
            "container_name": item.get("container_name"),
            "score": item.get("score"),
            "classification": item.get("classification"),
        })
    return by_image


def build_vulnerability_rows(scores, vulnerabilities_by_image):
    containers_by_image = build_image_container_index(scores)
    rows = []
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    for image, vulns in (vulnerabilities_by_image or {}).items():
        containers = containers_by_image.get(image) or [{"image": image}]
        for vuln in vulns:
            for container in containers:
                row = dict(vuln)
                row.update({
                    "host_name": container.get("host_name"),
                    "context": container.get("context"),
                    "container_name": container.get("container_name"),
                    "score": container.get("score"),
                    "classification": container.get("classification"),
                    "fix_available": bool(vuln.get("fixed_version")),
                })
                rows.append(row)
    rows.sort(key=lambda row: (
        severity_order.get(row.get("severity"), 9),
        0 if row.get("fix_available") else 1,
        -(int(row.get("score") or 0)),
        row.get("context") or "",
        row.get("container_name") or "",
        row.get("id") or "",
    ))
    return rows


def build_vulnerability_container_summary(scores, vulnerabilities_by_image):
    rows = []
    for item in scores or []:
        image = item.get("image")
        vulns = vulnerabilities_by_image.get(image, []) if image else []
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        fixable = 0
        for vuln in vulns:
            severity = vuln.get("severity") or "UNKNOWN"
            counts[severity if severity in counts else "UNKNOWN"] += 1
            if vuln.get("fixed_version"):
                fixable += 1
        total = sum(counts.values())
        rows.append({
            "host_name": item.get("host_name"),
            "context": item.get("context") or item.get("docker_context"),
            "container_name": item.get("container_name"),
            "image": image,
            "score": item.get("score"),
            "classification": item.get("classification"),
            "total": total,
            "critical": counts["CRITICAL"],
            "high": counts["HIGH"],
            "medium": counts["MEDIUM"],
            "low": counts["LOW"],
            "unknown": counts["UNKNOWN"],
            "fixable": fixable,
        })
    rows.sort(key=lambda row: (
        -(row.get("critical") or 0),
        -(row.get("high") or 0),
        -(row.get("total") or 0),
        -(int(row.get("score") or 0)),
        row.get("context") or "",
        row.get("container_name") or "",
    ))
    return rows


def render_dashboard():
    status = status_payload()
    summary = status.get("summary") or {}
    dependency_track = status.get("dependency_track") or {}
    alerts = status.get("alerts") or {}
    trivy = status.get("trivy") or {}
    vulns = status.get("vulnerability_summary") or {}
    top_rows = status.get("top_risks") or []
    context_rows = status.get("context_summary") or []
    cards = [
        ("Hosts", f"{summary.get('hosts_success', 0)}/{summary.get('hosts_total', 0)}"),
        ("Contextos", f"{summary.get('contexts_success', 0)}/{summary.get('contexts_total', 0)}"),
        ("Contextos bloqueados", active_alert_count(alerts, "context_scan_gap")),
        ("Containers", summary.get("containers_total", 0)),
        ("Imagens", summary.get("images_total", 0)),
        ("Achados", summary.get("findings_total", 0)),
    ]
    sections = {
        "dashboard": "active",
        "executive": "",
        "technical": "",
    }
    return render_shell(
        title="Container Security Monitor",
        eyebrow="Painel operacional",
        subtitle="Estado consolidado do inventario, riscos, Dependency-Track e alertas.",
        cards=cards,
        sections=sections,
        status_chips=render_status_chips(status),
        body_blocks=[
            render_executive_focus(status),
            render_history_comparison(status.get("history_comparison") or {}),
            render_vulnerability_focus(status),
            render_vulnerability_container_summary(status.get("vulnerability_container_summary") or []),
            render_vulnerability_table(status.get("vulnerability_rows") or []),
            render_score_factors_table(status.get("score_factor_rows") or []),
            render_table_panel(
                "Riscos prioritarios",
                ["Score", "Classe", "Contexto", "Host", "Container", "Imagem"],
                top_rows,
                lambda item: [
                    esc(item.get("score")),
                    esc(item.get("classification")),
                    esc(item.get("context")),
                    esc(item.get("host_name")),
                    esc(item.get("container_name")),
                    esc(item.get("image")),
                ],
                empty_message="Nenhum risco calculado ainda.",
            ),
            render_chart_grid(vulns, top_rows, context_rows),
            render_alerts_panel(status),
            render_summary_table(summary, dependency_track, alerts, trivy, vulns),
            render_table_panel(
                "Contextos prioritarios",
                ["Contexto", "Containers", "Score Max", "Score Medio", "Achados", "Criticos", "Altos"],
                context_rows,
                lambda item: [
                    esc(item.get("context")),
                    esc(item.get("containers")),
                    esc(item.get("score_max")),
                    esc(item.get("score_avg")),
                    esc(item.get("findings")),
                    esc(item.get("critical_containers")),
                    esc(item.get("high_containers")),
                ],
                empty_message="Nenhum contexto calculado ainda.",
            ),
        ],
    )


def render_report_page(kind_label, kind_key, source_name, query=None):
    status = status_payload()
    scan_state = manual_scan_state()
    summary = status.get("summary") or {}
    dependency_track = status.get("dependency_track") or {}
    alerts = status.get("alerts") or {}
    trivy = status.get("trivy") or {}
    vulns = status.get("vulnerability_summary") or {}
    selected_cve_container = (query or {}).get("cve_container", ["__all__"])[0] or "__all__"
    selected_severity = (query or {}).get("severity", ["__all__"])[0] or "__all__"
    selected_fix = (query or {}).get("fix", ["__all__"])[0] or "__all__"
    sections = {
        "dashboard": "",
        "executive": "active" if kind_key == "executive" else "",
        "technical": "active" if kind_key == "technical" else "",
    }
    title = f"Relatorio {kind_label}"
    subtitle = "Estrutura pronta para receber dados; os blocos vazios permanecem visiveis ate o primeiro scan."
    return render_shell(
        title=title,
        eyebrow=f"Relatorio {kind_label}",
        subtitle=subtitle,
        cards=[
            ("Fonte", source_name),
            ("Contextos", f"{summary.get('contexts_success', 0)}/{summary.get('contexts_total', 0)}"),
            ("Status", dependency_track.get("status") or "aguardando"),
            ("Inventario", status.get("inventory_status") or "aguardando"),
            ("Alertas", (alerts.get("status") or "aguardando")),
            ("Contextos bloqueados", active_alert_count(alerts, "context_scan_gap")),
            ("Vulnerabilidades", vulns.get("total", 0)),
        ],
        sections=sections,
        status_chips=build_report_chips(status, scan_state),
        export_href="/reports/executive.pdf" if kind_key == "executive" else None,
        body_blocks=[
            render_manual_scan_panel(scan_state) if kind_key == "technical" else "",
            render_executive_focus(status),
            render_history_comparison(status.get("history_comparison") or {}),
            render_vulnerability_focus(status),
            render_vulnerability_container_summary(status.get("vulnerability_container_summary") or []),
            render_vulnerability_table(
                status.get("vulnerability_rows") or [],
                selected_cve_container=selected_cve_container,
                selected_severity=selected_severity,
                selected_fix=selected_fix,
            ),
            render_score_factors_table(status.get("score_factor_rows") or [], selected_container=selected_cve_container),
            render_table_panel(
                "Top riscos",
                ["Score", "Classe", "Contexto", "Host", "Container", "Imagem"],
                status.get("top_risks") or [],
                lambda item: [
                    esc(item.get("score")),
                    esc(item.get("classification")),
                    esc(item.get("context")),
                    esc(item.get("host_name")),
                    esc(item.get("container_name")),
                    esc(item.get("image")),
                ],
                empty_message="Este relatorio ainda não tem riscos calculados.",
            ),
            render_chart_grid(vulns, status.get("top_risks") or [], status.get("context_summary") or []),
            render_alerts_panel(status),
            render_summary_table(summary, dependency_track, alerts, trivy, vulns),
            render_table_panel(
                "Contextos prioritarios",
                ["Contexto", "Containers", "Score Max", "Score Medio", "Achados", "Criticos", "Altos"],
                status.get("context_summary") or [],
                lambda item: [
                    esc(item.get("context")),
                    esc(item.get("containers")),
                    esc(item.get("score_max")),
                    esc(item.get("score_avg")),
                    esc(item.get("findings")),
                    esc(item.get("critical_containers")),
                    esc(item.get("high_containers")),
                ],
                empty_message="Nenhum contexto calculado ainda.",
            ),
        ],
    )


def render_container_report_page(slug):
    return render_shell(
        title=f"Container {slug}",
        eyebrow="Relatorio tecnico",
        subtitle="Pagina estruturada para o relatorio tecnico por container.",
        cards=[
            ("Container", slug),
            ("Status", "aguardando"),
            ("Severidade", "aguardando"),
            ("Host", "aguardando"),
            ("Imagem", "aguardando"),
            ("Score", "0"),
        ],
        sections={"dashboard": "", "executive": "", "technical": "active"},
        status_chips=[
            ("Estado", "aguardando", "neutral"),
            ("Container", "detalhe vazio", "neutral"),
            ("Login", "ativo", "good"),
            ("Dados", "sem scan", "warn"),
        ],
        body_blocks=[
            empty_panel(
                "Detalhe do container",
                "Sem dados ainda. Quando o primeiro scan for executado, esta pagina passa a exibir imagem, portas, mounts, capabilities, score e achados."
            ),
        ],
    )


def code_finding_key(item):
    raw = "|".join(str(item.get(key) or "") for key in ("client", "type", "id", "target", "package", "title"))
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def collect_code_findings(code=None):
    code = code if code is not None else (status_payload().get("code") or {})
    findings = []
    for client in code.get("results") or []:
        for finding in client.get("top_findings") or []:
            row = dict(finding)
            row["client"] = client.get("client")
            row["host_name"] = client.get("host_name")
            row["host_ip"] = client.get("host_ip")
            row["remote_path"] = client.get("remote_path")
            row["scan_path"] = client.get("scan_path")
            row["remediation"] = row.get("remediation") or recommended_code_action(row)
            row["key"] = code_finding_key(row)
            findings.append(row)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    findings.sort(key=lambda item: (
        severity_order.get(item.get("severity"), 9),
        item.get("client") or "",
        item.get("type") or "",
        item.get("id") or "",
    ))
    return findings


def render_code_finding_page(query=None):
    query = query or {}
    key = query.get("id", [""])[0]
    status = status_payload()
    code = status.get("code") or {}
    findings = collect_code_findings(code)
    item = next((row for row in findings if row.get("key") == key), None)
    if not item:
        return render_shell(
            title="Achado de codigo",
            eyebrow="Relatorio de codigo",
            subtitle="Achado nao encontrado no resumo mais recente.",
            cards=[
                ("Run", code.get("run_id") or "aguardando"),
                ("Status", "nao encontrado"),
                ("Cliente", "-"),
                ("Severidade", "-"),
                ("Tipo", "-"),
                ("ID", key or "-"),
            ],
            sections={"dashboard": "", "executive": "", "technical": "", "code": "active"},
            status_chips=render_status_chips(status),
            body_blocks=[empty_panel("Achado nao encontrado", "O achado pode pertencer a uma execucao antiga ou ter sido corrigido no scan atual.")],
        )

    details = [
        ("Cliente", item.get("client")),
        ("Host", item.get("host_name")),
        ("Diretorio", item.get("remote_path")),
        ("Escopo escaneado", item.get("scan_path")),
        ("Tipo", item.get("type")),
        ("Severidade", item.get("severity")),
        ("Classificacao", item.get("classification") or "-"),
        ("SLA", f"{item.get('sla_days')} dias" if item.get("sla_days") is not None else "-"),
        ("ID", item.get("id")),
        ("Alvo", item.get("target")),
        ("Pacote", item.get("package") or "-"),
        ("Versao instalada", item.get("installed_version") or "-"),
        ("Versao corrigida", item.get("fixed_version") or "-"),
        ("Resumo", item.get("title")),
        ("Acao recomendada", item.get("remediation")),
    ]
    rows = "".join(f"<tr><th>{esc(label)}</th><td>{esc(value)}</td></tr>" for label, value in details)
    return render_shell(
        title="Achado de codigo",
        eyebrow="Relatorio de codigo",
        subtitle=f"{item.get('client')} / {item.get('id')}",
        cards=[
            ("Cliente", item.get("client")),
            ("Severidade", item.get("severity")),
            ("Tipo", item.get("type")),
            ("Pacote", item.get("package") or "-"),
            ("Corrigida", item.get("fixed_version") or "-"),
            ("Run", code.get("run_id") or "aguardando"),
        ],
        sections={"dashboard": "", "executive": "", "technical": "", "code": "active"},
        status_chips=render_status_chips(status),
        body_blocks=[
            section("Detalhe do achado", "Dados normalizados do Trivy para tratamento operacional.", f"<table>{rows}</table>"),
            section("Correcao", "", f'<div class="empty">{esc(item.get("remediation"))}</div>'),
        ],
    )


def render_code_csv():
    status = status_payload()
    findings = collect_code_findings(status.get("code") or {})
    fields = ["client", "host_name", "scan_path", "type", "severity", "classification", "sla_days", "id", "target", "package", "installed_version", "fixed_version", "title", "remediation"]
    handle = io.StringIO()
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    for item in findings:
        writer.writerow({field: item.get(field) for field in fields})
    return handle.getvalue()


def pdf_escape(value):
    data = str(value if value is not None else "").encode("latin-1", errors="replace")
    return data.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")


def wrap_pdf_line(value, width=92):
    words = str(value if value is not None else "").replace("\n", " ").split()
    lines = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) > width and current:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines or [""]


def simple_pdf_bytes(title, lines):
    page_width = 595
    page_height = 842
    margin_x = 44
    margin_y = 54
    line_height = 14
    max_lines = int((page_height - (margin_y * 2)) / line_height)
    pages = []
    current = []
    for line in lines:
        for part in wrap_pdf_line(line):
            if len(current) >= max_lines:
                pages.append(current)
                current = []
            current.append(part)
    if current:
        pages.append(current)
    if not pages:
        pages = [[]]

    objects = []
    catalog_id = 1
    pages_id = 2
    font_id = 3
    page_ids = []
    content_ids = []
    next_id = 4
    for _ in pages:
        page_ids.append(next_id)
        content_ids.append(next_id + 1)
        next_id += 2

    objects.append((catalog_id, b"<< /Type /Catalog /Pages 2 0 R >>"))
    kids = b" ".join(f"{pid} 0 R".encode("ascii") for pid in page_ids)
    objects.append((pages_id, b"<< /Type /Pages /Kids [" + kids + b"] /Count " + str(len(page_ids)).encode("ascii") + b" >>"))
    objects.append((font_id, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"))

    for index, page_lines in enumerate(pages):
        content = bytearray()
        content.extend(b"BT\n/F1 16 Tf\n")
        content.extend(f"{margin_x} {page_height - margin_y} Td\n".encode("ascii"))
        content.extend(b"(" + pdf_escape(title) + b") Tj\n")
        content.extend(b"/F1 10 Tf\n")
        content.extend(f"0 -{line_height * 2} Td\n".encode("ascii"))
        for line in page_lines:
            content.extend(b"(" + pdf_escape(line) + b") Tj\n")
            content.extend(f"0 -{line_height} Td\n".encode("ascii"))
        content.extend(b"ET\n")
        stream = b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n" + bytes(content) + b"endstream"
        objects.append((content_ids[index], stream))
        page = (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 "
            + f"{page_width} {page_height}".encode("ascii")
            + b"] /Resources << /Font << /F1 3 0 R >> >> /Contents "
            + f"{content_ids[index]} 0 R".encode("ascii")
            + b" >>"
        )
        objects.append((page_ids[index], page))

    objects.sort(key=lambda item: item[0])
    output = bytearray(b"%PDF-1.4\n")
    offsets = {}
    for obj_id, body in objects:
        offsets[obj_id] = len(output)
        output.extend(f"{obj_id} 0 obj\n".encode("ascii"))
        output.extend(body)
        output.extend(b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for obj_id, _ in objects:
        output.extend(f"{offsets[obj_id]:010d} 00000 n \n".encode("ascii"))
    output.extend(
        b"trailer\n<< /Size "
        + str(len(objects) + 1).encode("ascii")
        + b" /Root 1 0 R >>\nstartxref\n"
        + str(xref).encode("ascii")
        + b"\n%%EOF\n"
    )
    return bytes(output)


def render_code_pdf():
    status = status_payload()
    code = status.get("code") or {}
    findings = collect_code_findings(code)
    lines = [
            f"Run: {code.get('run_id') or 'aguardando'}",
            f"Status: {code.get('status') or 'aguardando'}",
            f"Clientes: {code.get('clients_total', 0)}",
            f"Historico: novos={((code.get('history') or {}).get('new', 0))}, persistentes={((code.get('history') or {}).get('persistent', 0))}, corrigidos={((code.get('history') or {}).get('fixed', 0))}",
            "",
    ]
    if not findings:
        lines.append("Nenhum achado de codigo encontrado.")
    for item in findings[:120]:
        lines.extend([
            f"Cliente: {item.get('client')} | Severidade: {item.get('severity')} | Tipo: {item.get('type')}",
            f"SLA: {item.get('sla_days', '-')} dias | Classificacao: {item.get('classification', '-')}",
            f"ID: {item.get('id')} | Alvo: {item.get('target')}",
            f"Resumo: {item.get('title')}",
            f"Acao: {item.get('remediation')}",
            "",
        ])
    return simple_pdf_bytes("Relatorio SAST", lines)


def render_code_page(query=None):
    status = status_payload()
    code = status.get("code") or {}
    selected_client = (query or {}).get("client", ["__all__"])[0] or "__all__"
    results = code.get("results") or []
    if selected_client != "__all__":
        visible = [item for item in results if item.get("client") == selected_client]
    else:
        visible = results
    options = [f'<option value="__all__" {"selected" if selected_client == "__all__" else ""}>Todos os clientes</option>']
    for item in results:
        client = item.get("client") or "unknown"
        options.append(f'<option value="{esc(client)}" {"selected" if selected_client == client else ""}>{esc(client)}</option>')
    totals = code.get("totals") or {}
    severity = totals.get("severity_counts") or {}
    history = code.get("history") or {}
    body = [
        section(
            "SAST por cliente",
            "Scan de codigo/projeto com Semgrep, checks PHP e Trivy restrito a secrets/misconfig. Esta visao e separada das imagens de container.",
            f"""
            <div class="status-strip">
              {pill("Clientes", code.get("clients_total", 0))}
              {pill("Sucesso", code.get("success", 0))}
              {pill("SAST", totals.get("code_findings", 0))}
              {pill("Secrets", totals.get("secrets", 0))}
              {pill("Misconfig", totals.get("misconfigurations", 0))}
              {pill("Ignorados", totals.get("suppressed_findings", code.get("suppressed_findings", 0)))}
              {pill("Criticas", severity.get("CRITICAL", 0))}
            </div>
            """,
        ),
        section(
            "Historico de codigo",
            "Compara a execucao atual com a anterior: novo, persistente e corrigido.",
            f"""
            <div class="status-strip">
              {pill("Novos", history.get("new", 0))}
              {pill("Persistentes", history.get("persistent", 0))}
              {pill("Corrigidos", history.get("fixed", 0))}
              {pill("Execucao anterior", history.get("previous_run_id") or "-")}
            </div>
            """,
        ),
        section(
            "Filtro",
            "",
            f"""
            <form class="table-tools" method="get" action="/reports/code">
              <label>Cliente
                <select name="client">{''.join(options)}</select>
              </label>
              <button class="action primary" type="submit">Aplicar</button>
              <span class="table-count">{len(visible)} clientes exibidos</span>
            </form>
            <div class="table-tools" style="margin-top: 10px;">
              <a class="action" href="/reports/code.csv">Exportar CSV</a>
              <a class="action" href="/reports/code.pdf">Exportar PDF</a>
            </div>
            """,
        ),
        render_code_clients_table(visible),
        render_code_findings_table(visible),
    ]
    return render_shell(
        title="Codigo",
        eyebrow="Relatorio SAST",
        subtitle="Achados de codigo, secrets e configuracao nos diretorios ativos dos clientes.",
        cards=[
            ("Run", code.get("run_id") or "aguardando"),
            ("Status", code.get("status") or "aguardando"),
            ("Clientes", code.get("clients_total", 0)),
            ("SAST", totals.get("code_findings", 0)),
            ("Secrets", totals.get("secrets", 0)),
            ("Ignorados", totals.get("suppressed_findings", 0)),
            ("Novos", history.get("new", 0)),
        ],
        sections={"dashboard": "", "executive": "", "technical": "", "code": "active"},
        status_chips=render_status_chips(status),
        body_blocks=body,
    )


def render_code_clients_table(rows):
    return render_table_panel(
        "Clientes escaneados",
        ["Cliente", "Host", "Diretorio", "Status", "SAST", "Secrets", "Misconfig", "Ignorados", "Criticas", "Altas"],
        rows,
        lambda item: [
            esc(item.get("client")),
            esc(item.get("host_name")),
            f'<span class="cell-sub">{esc(item.get("remote_path"))}</span>',
            esc(item.get("status")),
            esc(item.get("code_findings", 0)),
            esc(item.get("secrets", 0)),
            esc(item.get("misconfigurations", 0)),
            esc(item.get("suppressed_findings", 0)),
            esc((item.get("severity_counts") or {}).get("CRITICAL", 0)),
            esc((item.get("severity_counts") or {}).get("HIGH", 0)),
        ],
        empty_message="Nenhum scan de codigo executado ainda.",
    )


def render_code_findings_table(rows):
    findings = []
    for item in rows:
        findings.extend(collect_code_findings({"results": [item]}))
    if not findings:
        return section("Achados de codigo", "", '<div class="empty">Nenhum achado de codigo encontrado para o filtro atual.</div>')
    return render_table_panel(
        "Achados de codigo",
        ["Cliente", "Tipo", "Sev.", "SLA", "ID", "Alvo", "Pacote", "Corrigida", "Resumo", "Acao recomendada", "Detalhe"],
        findings[:200],
        lambda item: [
            esc(item.get("client")),
            esc(item.get("type")),
            severity_badge(item.get("severity")),
            esc(f"{item.get('sla_days')} dias" if item.get("sla_days") is not None else "-"),
            f'<span class="cell-strong">{esc(item.get("id"))}</span>',
            f'<span class="cell-sub">{esc(item.get("target"))}</span>',
            esc(item.get("package")),
            f'<span class="{"fix-yes" if item.get("fixed_version") else "fix-no"}">{esc(item.get("fixed_version") or "-")}</span>',
            esc(item.get("title")),
            esc(item.get("remediation") or recommended_code_action(item)),
            f'<a class="table-action" href="/reports/code/finding?{urlencode({"id": item.get("key")})}">Abrir</a>',
        ],
        empty_message="Nenhum achado de codigo encontrado para o filtro atual.",
    )


def recommended_code_action(item):
    finding_type = item.get("type")
    fixed = item.get("fixed_version")
    package = item.get("package") or "pacote afetado"
    severity = item.get("severity") or "UNKNOWN"
    if finding_type == "vulnerability":
        if fixed:
            return f"Atualizar {package} para {fixed} e validar compatibilidade no projeto."
        if severity in {"CRITICAL", "HIGH"}:
            return "Sem versao corrigida informada; avaliar mitigacao, troca da dependencia ou compensacao de risco."
        return "Monitorar a dependencia e atualizar quando houver versao corrigida."
    if finding_type == "secret":
        rule = item.get("id") or "secret"
        return f"Remover o {rule}, rotacionar a credencial e substituir por variavel de ambiente ou secret manager."
    if finding_type == "misconfiguration":
        return "Revisar a configuracao apontada pelo Trivy e aplicar o ajuste recomendado no arquivo alvo."
    if finding_type == "lfi":
        return "Validar o parametro contra lista permitida, normalizar caminho com realpath e bloquear ../ antes do include/require."
    return "Revisar o achado e documentar correcao ou aceite de risco."


def render_shell(title, eyebrow, subtitle, cards, sections, body_blocks, status_chips=None, export_href=None):
    nav = [
        ("dashboard", "/", "Painel"),
        ("executive", "/reports/executive", "Gerencial"),
        ("technical", "/reports/technical", "Tecnico"),
        ("code", "/reports/code", "Codigo"),
        ("settings", "/settings", "Configuracao"),
        ("api", "/api/status", "JSON"),
        ("metrics", "/metrics", "Metricas"),
    ]
    nav_html = "".join(
        f'<a class="nav-item {sections.get(key, "")}" href="{href}"><span class="nav-dot"></span><span>{label}</span></a>'
        for key, href, label in nav
    )
    cards_html = "".join(
        f"""
        <section class="card">
          <div class="card-label">{esc(label)}</div>
          <div class="card-value">{esc(value)}</div>
        </section>
        """
        for label, value in cards
    )
    chips_html = "".join(
        render_status_chip(label, value, tone)
        for label, value, tone in (status_chips or [])
    )
    body = "".join(body_blocks)
    return f"""<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <title>{esc(title)}</title>
    <style>
    :root {{
      color-scheme: light;
      --bg: #f4f7fb;
      --surface: #ffffff;
      --surface-2: #f8fafc;
      --surface-3: #eef4fb;
      --border: #d9e2ec;
      --ink: #172033;
      --muted: #64748b;
      --accent: #2563eb;
      --accent-2: #0891b2;
      --accent-3: #7c3aed;
      --good: #059669;
      --warn: #d97706;
      --danger: #dc2626;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background:
        linear-gradient(180deg, #f8fbff 0%, #eef4fb 100%),
        var(--bg);
      color: var(--ink);
    }}
    .shell {{
      display: grid;
      grid-template-columns: 184px minmax(0, 1fr);
      min-height: 100vh;
    }}
    .sidebar {{
      position: sticky;
      top: 0;
      height: 100vh;
      background: #ffffff;
      border-right: 1px solid var(--border);
      padding: 18px 14px;
      display: grid;
      gap: 16px;
      align-content: start;
      overflow-y: auto;
      overflow-x: hidden;
    }}
    .brandmark {{
      width: 48px;
      height: 48px;
      border-radius: 14px;
      display: grid;
      place-items: center;
      background: linear-gradient(180deg, #2563eb 0%, #0f4ca8 100%);
      color: #fff;
      font-size: 18px;
      font-weight: 700;
      margin: 0 auto;
      box-shadow: 0 10px 24px rgba(11, 92, 173, 0.25);
    }}
    .sidebar .nav-stack {{
      display: grid;
      gap: 8px;
      min-width: 0;
    }}
    .nav-item {{
      display: grid;
      grid-template-columns: 12px 1fr;
      gap: 10px;
      align-items: center;
      padding: 10px 12px;
      text-decoration: none;
      color: var(--ink);
      background: #f8fafc;
      border: 1px solid var(--border);
      border-radius: 10px;
      font-size: 12px;
      font-weight: 700;
      min-width: 0;
    }}
    .nav-item span:last-child {{
      min-width: 0;
      overflow-wrap: anywhere;
    }}
    .nav-item .nav-dot {{
      width: 10px;
      height: 10px;
      border-radius: 999px;
      background: #94a3b8;
    }}
    .nav-item.active {{
      background: #eff6ff;
      border-color: #93c5fd;
    }}
    .nav-item.active .nav-dot {{
      background: #6fa8ff;
    }}
    .sidebar .rail-title {{
      font-size: 11px;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--muted);
      margin: 6px 0 0;
      text-align: center;
    }}
    .sidebar .side-actions {{
      display: grid;
      gap: 8px;
      min-width: 0;
    }}
    .sidebar .action {{
      justify-content: center;
      width: 100%;
      padding: 10px 12px;
    }}
    .sidebar .chips-wrap {{
      display: grid;
      gap: 8px;
      min-width: 0;
    }}
    .workspace {{
      min-width: 0;
      padding: 18px 18px 24px;
      display: grid;
      gap: 16px;
    }}
    .topbar {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 18px;
      padding: 22px 24px;
      border: 1px solid var(--border);
      background: var(--surface);
      margin: 0;
      border-radius: 8px;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.28);
      position: relative;
      overflow: hidden;
    }}
    .topbar::before {{
      content: "";
      position: absolute;
      inset: 0 auto 0 0;
      width: 7px;
      background: linear-gradient(180deg, var(--accent) 0%, var(--accent-2) 55%, var(--accent-3) 100%);
    }}
    .brand {{
      display: grid;
      gap: 8px;
      padding-left: 8px;
      flex: 1;
    }}
    .eyebrow-row {{
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }}
    .eyebrow {{
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      color: var(--muted);
    }}
    h1 {{
      margin: 0;
      font-size: 30px;
      line-height: 1.15;
    }}
    .subtitle {{
      margin: 0;
      color: var(--muted);
      max-width: 78ch;
    }}
    .status-chips {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-top: 2px;
    }}
    .chip {{
      display: inline-flex;
      flex-direction: column;
      gap: 2px;
      min-width: 0;
      padding: 10px 12px;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--surface-2);
      box-shadow: 0 6px 16px rgba(0, 0, 0, 0.18);
    }}
    .chip-label {{
      font-size: 11px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--muted);
    }}
    .chip-value {{
      font-size: 13px;
      font-weight: 700;
      color: var(--ink);
      overflow-wrap: anywhere;
    }}
    .chip.good {{ border-left: 4px solid var(--good); }}
    .chip.warn {{ border-left: 4px solid var(--warn); }}
    .chip.danger {{ border-left: 4px solid var(--danger); }}
    .chip.neutral {{ border-left: 4px solid var(--accent); }}
    .topactions {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      justify-content: flex-end;
      align-items: center;
    }}
    .action {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 10px 14px;
      border: 1px solid var(--border);
      background: #f8fafc;
      color: var(--ink);
      text-decoration: none;
      min-width: 0;
      overflow-wrap: anywhere;
      white-space: nowrap;
      border-radius: 8px;
      transition: transform 0.15s ease, box-shadow 0.15s ease, border-color 0.15s ease;
      box-shadow: 0 4px 14px rgba(0, 0, 0, 0.16);
      appearance: none;
      cursor: pointer;
    }}
    .action:hover {{
      transform: translateY(-1px);
      border-color: #93c5fd;
      box-shadow: 0 8px 18px rgba(16, 32, 51, 0.09);
    }}
    .action.primary {{
      background: #0b5cad;
      color: white;
      border-color: transparent;
    }}
    .nav {{
      display: none;
    }}
    .navlink {{
      padding: 10px 14px;
      border: 1px solid transparent;
      background: var(--surface);
      color: var(--ink);
      text-decoration: none;
      border-radius: 8px;
      box-shadow: inset 0 0 0 1px rgba(42, 47, 57, 0.8);
      transition: background 0.15s ease, transform 0.15s ease, box-shadow 0.15s ease;
    }}
    .navlink:hover {{
      transform: translateY(-1px);
      box-shadow: inset 0 0 0 1px rgba(111, 168, 255, 0.22), 0 6px 14px rgba(0, 0, 0, 0.16);
    }}
    .navlink.active {{
      background: #eff6ff;
      color: var(--ink);
      box-shadow: none;
    }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 12px;
      margin: 0;
    }}
    .card {{
      background: var(--surface);
      border: 1px solid var(--border);
      padding: 16px 16px 15px;
      min-height: 92px;
      border-radius: 8px;
      box-shadow: 0 10px 28px rgba(0, 0, 0, 0.18);
      position: relative;
      overflow: hidden;
    }}
    .card-label {{
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}
    .card-value {{
      margin-top: 10px;
      font-size: 26px;
      font-weight: 700;
      line-height: 1.15;
      overflow-wrap: anywhere;
    }}
    .card:nth-child(1) {{ border-top: 4px solid var(--accent); }}
    .card:nth-child(2) {{ border-top: 4px solid var(--accent-2); }}
    .card:nth-child(3) {{ border-top: 4px solid var(--accent-3); }}
    .card:nth-child(4) {{ border-top: 4px solid var(--good); }}
    .card:nth-child(5) {{ border-top: 4px solid var(--warn); }}
    .card:nth-child(6) {{ border-top: 4px solid var(--danger); }}
    .card:nth-child(7) {{ border-top: 4px solid var(--accent); }}
    .section {{
      background: var(--surface);
      border: 1px solid var(--border);
      margin: 0;
      padding: 18px;
      border-radius: 8px;
      box-shadow: 0 10px 26px rgba(0, 0, 0, 0.16);
    }}
    .section h2 {{
      margin: 0 0 10px;
      font-size: 18px;
      display: flex;
      align-items: center;
      gap: 10px;
    }}
    .subtext {{
      margin: 0 0 12px;
      color: var(--muted);
    }}
    .status-strip {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
    }}
    .pill {{
      display: flex;
      flex-direction: column;
      gap: 6px;
      padding: 14px;
      background: linear-gradient(180deg, #ffffff 0%, var(--surface-2) 100%);
      border: 1px solid var(--border);
      min-height: 72px;
      border-radius: 8px;
    }}
    .pill span:first-child {{
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
    }}
    .pill strong {{
      font-size: 15px;
      overflow-wrap: anywhere;
    }}
    table {{
      border-collapse: collapse;
      width: 100%;
      overflow: hidden;
      border-radius: 8px;
    }}
    th, td {{
      border: 1px solid var(--border);
      padding: 10px;
      vertical-align: top;
      text-align: left;
    }}
    th {{
      background: linear-gradient(180deg, #f1f5f9 0%, #e8eef6 100%);
      color: var(--ink);
      font-size: 13px;
    }}
    .empty {{
      padding: 18px;
      border: 1px dashed var(--border);
      background: #f8fafc;
      color: var(--muted);
      border-radius: 8px;
    }}
    .alert-badge {{
      display: inline-flex;
      align-items: center;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      white-space: nowrap;
    }}
    .alert-badge.critical {{
      background: #fee2e2;
      color: var(--danger);
    }}
    .alert-badge.warning {{
      background: #fef3c7;
      color: var(--warn);
    }}
    .alert-badge.info {{
      background: #dbeafe;
      color: var(--accent);
    }}
    .alert-observed {{
      display: block;
      white-space: normal;
      overflow-wrap: anywhere;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      font-size: 12px;
      color: var(--ink);
    }}
    .chart-shell {{
      display: grid;
      gap: 12px;
      align-items: center;
      min-width: 0;
    }}
    .chart-svg {{
      width: 100%;
      height: auto;
      display: block;
    }}
    .chart-svg.donut {{
      width: min(100%, 260px);
      max-height: 260px;
      justify-self: center;
    }}
    .chart-svg.bars {{
      max-height: 260px;
    }}
    .chart-svg text {{
      fill: var(--muted);
      font-family: inherit;
    }}
    .chart-main-value {{
      font-size: 32px;
      fill: var(--ink) !important;
      font-weight: 700;
    }}
    .chart-main-label {{
      font-size: 13px;
    }}
    .chart-axis {{
      font-size: 11px;
      fill: var(--muted);
    }}
    .chart-value {{
      font-size: 11px;
      fill: var(--ink) !important;
      font-weight: 700;
    }}
    .chart-baseline, .chart-gridline {{
      stroke: var(--border);
      stroke-width: 1;
    }}
    .chart-gridline {{
      opacity: 0.65;
    }}
    .chart-legend {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px 16px;
    }}
    .chart-legend-item {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      color: var(--muted);
      font-size: 12px;
    }}
    .chart-legend-item strong {{
      color: var(--ink);
    }}
    .chart-legend-item .swatch {{
      width: 10px;
      height: 10px;
      border-radius: 999px;
      display: inline-block;
    }}
    .severity {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 78px;
      padding: 4px 8px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 800;
      color: #101318;
      text-transform: uppercase;
    }}
    .severity.CRITICAL {{ background: var(--danger); }}
    .severity.HIGH {{ background: var(--warn); }}
    .severity.MEDIUM {{ background: #e8df8b; }}
    .severity.LOW {{ background: var(--good); }}
    .severity.UNKNOWN {{ background: var(--accent); }}
    .cell-strong {{
      font-weight: 800;
      color: var(--ink);
    }}
    .cell-sub {{
      display: block;
      color: var(--muted);
      font-size: 12px;
      overflow-wrap: anywhere;
      margin-top: 2px;
    }}
    .fix-yes {{
      color: var(--good);
      font-weight: 800;
    }}
    .fix-no {{
      color: var(--muted);
    }}
    .table-tools {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
      margin-bottom: 14px;
    }}
    .table-tools label {{
      display: grid;
      gap: 6px;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }}
    .table-tools select, .table-tools input, .table-tools textarea {{
      min-width: 160px;
      max-width: min(520px, 100%);
      padding: 10px 12px;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: #ffffff;
      color: var(--ink);
      font: inherit;
      text-transform: none;
      letter-spacing: 0;
    }}
    .table-tools input[type="number"] {{
      min-width: 110px;
      width: 120px;
    }}
    .table-tools input[type="checkbox"] {{
      min-width: 0;
      width: auto;
      padding: 0;
    }}
    .table-count {{
      color: var(--muted);
      font-size: 13px;
    }}
    .is-hidden {{
      display: none;
    }}
    .main-column {{
      display: grid;
      gap: 16px;
    }}
    @media (max-width: 900px) {{
      .shell {{ grid-template-columns: 1fr; }}
      .sidebar {{ position: static; height: auto; grid-template-columns: repeat(5, minmax(0, 1fr)); }}
      .sidebar .rail-title, .sidebar .side-actions, .sidebar .chips-wrap {{ display: none; }}
      .brandmark {{ margin: 0; }}
      .topbar {{ display: block; }}
      .topactions {{ justify-content: flex-start; margin-top: 14px; }}
    }}
  </style>
</head>
<body>
  <div class="shell">
    <aside class="sidebar" aria-label="Menu lateral">
      <div class="brandmark">CSM</div>
      <div class="rail-title">Monitor</div>
      <nav class="nav-stack">{nav_html}</nav>
      <div class="rail-title">Estado</div>
      <div class="chips-wrap">{chips_html}</div>
    </aside>
    <main class="workspace">
      <header class="topbar">
        <div class="brand">
          <div class="eyebrow-row">
            <div class="eyebrow">{esc(eyebrow)}</div>
          </div>
          <h1>{esc(title)}</h1>
          <p class="subtitle">{esc(subtitle)}</p>
          <div class="status-chips">{chips_html}</div>
        </div>
        <div class="topactions">
          <a class="action" href="?filters=1">Filtros</a>
          {f'<a class="action primary" href="{esc(export_href)}" target="_blank" rel="noopener">Exportar PDF</a>' if export_href else ''}
          <a class="action" href="/login">Login</a>
        </div>
      </header>
      <section class="cards">{cards_html}</section>
      <div class="main-column">{body}</div>
    </main>
  </div>
</body>
</html>
"""


def render_status_strip(status):
    dependency_track = status.get("dependency_track") or {}
    alerts = status.get("alerts") or {}
    trivy = status.get("trivy") or {}
    return section(
        "Estado geral",
        "Visão rápida do sistema. Os blocos permanecem visíveis mesmo sem um scan executado.",
        f"""
        <div class="status-strip">
          {pill("Inventario", status.get("inventory_status") or "aguardando")}
          {pill("Dependency-Track", dependency_track.get("status") or "aguardando")}
          {pill("Analise DT", dependency_track.get("analysis_status") or "aguardando")}
          {pill("Trivy", trivy.get("images_total") or 0)}
          {pill("Alertas", alerts.get("status") or "aguardando")}
        </div>
        """
    )


def active_alert_count(alerts, rule_id):
    items = alerts.get("active_rules") or alerts.get("alerts") or []
    return sum(1 for item in items if item.get("id") == rule_id and item.get("active"))


def render_alerts_panel(status):
    alerts = status.get("alerts") or {}
    active = alerts.get("active_rules") or alerts.get("alerts") or []
    if not active:
        return section(
            "Alertas ativos",
            "Nenhum alerta derivado no momento.",
            '<div class="empty">A dashboard passa a destacar aqui qualquer contexto que nao puder ser escaneado.</div>',
        )

    rows = []
    for item in active:
        severity = item.get("severity") or "warning"
        observed = item.get("observed")
        if isinstance(observed, (dict, list)):
            observed = json.dumps(observed, ensure_ascii=False, sort_keys=True)
        rows.append(
            "<tr>"
            f"<td>{esc(item.get('id'))}</td>"
            f"<td><span class='alert-badge {esc(severity)}'>{esc(severity)}</span></td>"
            f"<td>{esc(item.get('message'))}</td>"
            f"<td><span class='alert-observed'>{esc(observed)}</span></td>"
            "</tr>"
        )
    return section(
        "Alertas ativos",
        "Qualquer contexto impossivel de coletar aparece aqui em destaque.",
        "<table><thead><tr><th>Regra</th><th>Severidade</th><th>Mensagem</th><th>Observado</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>",
    )


def severity_badge(severity):
    value = str(severity or "UNKNOWN").upper()
    if value not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}:
        value = "UNKNOWN"
    return f'<span class="severity {esc(value)}">{esc(value)}</span>'


def render_vulnerability_focus(status):
    vulns = status.get("vulnerability_summary") or {}
    severity_counts = vulns.get("severity_counts") or {}
    rows = [
        ("Total", vulns.get("total", 0)),
        ("Criticas", severity_counts.get("CRITICAL", 0)),
        ("Altas", severity_counts.get("HIGH", 0)),
        ("Medias", severity_counts.get("MEDIUM", 0)),
        ("Baixas", severity_counts.get("LOW", 0)),
        ("Imagens", (status.get("trivy") or {}).get("images_total") or 0),
    ]
    return section(
        "Vulnerabilidades",
        "Leitura direta do Trivy: total por severidade e imagens analisadas.",
        f'<div class="status-strip">{"".join(pill(label, value) for label, value in rows)}</div>',
    )


def signed_delta(value):
    value = int(value or 0)
    if value > 0:
        return f"+{value}"
    return str(value)


def render_history_comparison(history):
    current = history.get("current") or {}
    previous = history.get("previous") or {}
    deltas = history.get("deltas") or {}
    if not previous:
        return section("Historico comparativo", "", '<div class="empty">Ainda nao ha execucao anterior suficiente para comparar.</div>')
    return section(
        "Historico comparativo",
        f"Comparando {current.get('run_id')} contra {previous.get('run_id')}. Valores positivos indicam piora.",
        f"""
        <div class="status-strip">
          {pill("CVEs", f"{current.get('total', 0)} ({signed_delta(deltas.get('total'))})")}
          {pill("Criticas", f"{current.get('critical', 0)} ({signed_delta(deltas.get('critical'))})")}
          {pill("Altas", f"{current.get('high', 0)} ({signed_delta(deltas.get('high'))})")}
          {pill("Score max", f"{current.get('max_score', 0)} ({signed_delta(deltas.get('max_score'))})")}
        </div>
        """,
    )


def render_executive_focus(status):
    vulns = status.get("vulnerability_summary") or {}
    sev = vulns.get("severity_counts") or {}
    containers = status.get("vulnerability_container_summary") or []
    alerts = status.get("alerts") or {}
    worst = containers[0] if containers else {}
    actions = []
    if sev.get("CRITICAL", 0):
        actions.append(f"Priorizar CVEs criticas: {sev.get('CRITICAL')} ocorrencias.")
    if worst:
        actions.append(f"Comecar por {worst.get('context')} / {worst.get('container_name')} ({worst.get('critical')} criticas, {worst.get('high')} altas).")
    if (alerts.get("totals") or {}).get("active"):
        actions.append(f"Resolver {((alerts.get('totals') or {}).get('active'))} alertas ativos.")
    if not actions:
        actions.append("Sem acao critica imediata detectada nesta execucao.")
    rows = "".join(f"<li>{esc(item)}</li>" for item in actions[:5])
    return section(
        "Resumo executivo",
        "O que olhar primeiro nesta execucao.",
        f"<ol class=\"priority\">{rows}</ol>",
    )


def render_vulnerability_container_summary(rows):
    return render_table_panel(
        "Containers com mais CVEs",
        ["Container", "Contexto", "Imagem", "Score", "Total", "Criticas", "Altas", "Com correcao"],
        rows[:12],
        lambda item: [
            f'<span class="cell-strong">{esc(item.get("container_name"))}</span><span class="cell-sub">{esc(item.get("host_name"))}</span>',
            esc(item.get("context")),
            f'<span class="cell-sub">{esc(item.get("image"))}</span>',
            esc(item.get("score")),
            esc(item.get("total")),
            esc(item.get("critical")),
            esc(item.get("high")),
            esc(item.get("fixable")),
        ],
        empty_message="Nenhuma vulnerabilidade detalhada carregada ainda.",
    )


def render_vulnerability_table(rows, selected_cve_container="__all__", selected_severity="__all__", selected_fix="__all__"):
    rows = rows[:200]
    if not rows:
        return section("CVEs prioritarias", "", '<div class="empty">Nenhuma CVE detalhada encontrada nos JSONs do Trivy.</div>')

    containers = []
    seen = set()
    for item in rows:
        key = f"{item.get('context') or 'sem contexto'}|{item.get('container_name') or 'sem container'}|{item.get('image') or 'sem imagem'}"
        if key in seen:
            continue
        seen.add(key)
        containers.append({
            "key": key,
            "label": f"{item.get('context') or 'sem contexto'} / {item.get('container_name') or 'sem container'}",
            "image": item.get("image") or "",
        })

    selected_cve_container = selected_cve_container or "__all__"
    selected_severity = (selected_severity or "__all__").upper()
    selected_fix = selected_fix or "__all__"
    valid_keys = {item["key"] for item in containers}
    if selected_cve_container != "__all__" and selected_cve_container not in valid_keys:
        selected_cve_container = "__all__"

    options = [f'<option value="__all__" {"selected" if selected_cve_container == "__all__" else ""}>Todos os containers</option>']
    options.extend(
        f'<option value="{esc(item["key"])}" {"selected" if item["key"] == selected_cve_container else ""}>{esc(item["label"])} - {esc(item["image"])}</option>'
        for item in containers
    )

    visible_rows = [
        item for item in rows
        if selected_cve_container == "__all__"
        or f"{item.get('context') or 'sem contexto'}|{item.get('container_name') or 'sem container'}|{item.get('image') or 'sem imagem'}" == selected_cve_container
    ]
    if selected_severity != "__ALL__":
        visible_rows = [item for item in visible_rows if (item.get("severity") or "UNKNOWN").upper() == selected_severity]
    if selected_fix == "yes":
        visible_rows = [item for item in visible_rows if item.get("fixed_version")]
    elif selected_fix == "no":
        visible_rows = [item for item in visible_rows if not item.get("fixed_version")]

    severity_options = []
    for value, label in (("__all__", "Todas"), ("CRITICAL", "Criticas"), ("HIGH", "Altas"), ("MEDIUM", "Medias"), ("LOW", "Baixas"), ("UNKNOWN", "Desconhecidas")):
        severity_options.append(f'<option value="{esc(value)}" {"selected" if selected_severity == value.upper() else ""}>{esc(label)}</option>')
    fix_options = []
    for value, label in (("__all__", "Todas"), ("yes", "Com correcao"), ("no", "Sem correcao")):
        fix_options.append(f'<option value="{esc(value)}" {"selected" if selected_fix == value else ""}>{esc(label)}</option>')

    body_rows = []
    for item in visible_rows:
        key = f"{item.get('context') or 'sem contexto'}|{item.get('container_name') or 'sem container'}|{item.get('image') or 'sem imagem'}"
        body_rows.append(
            f'<tr>'
            f'<td>{severity_badge(item.get("severity"))}</td>'
            f'<td><span class="cell-strong">{esc(item.get("container_name"))}</span><span class="cell-sub">{esc(item.get("image"))}</span></td>'
            f'<td>{esc(item.get("context"))}</td>'
            f'<td><span class="cell-strong">{esc(item.get("id"))}</span></td>'
            f'<td>{esc(item.get("package"))}</td>'
            f'<td>{esc(item.get("installed_version"))}</td>'
            f'<td><span class="{"fix-yes" if item.get("fixed_version") else "fix-no"}">{esc(item.get("fixed_version") or "sem fix")}</span></td>'
            f'<td>{esc(item.get("title"))}</td>'
            f'<td>{esc(item.get("remediation"))}</td>'
            '</tr>'
        )

    return section(
        "CVEs prioritarias",
        "",
        f"""
        <form class="table-tools" method="get" action="/reports/technical">
          <label>Filtrar por container
            <select name="cve_container">
              {''.join(options)}
            </select>
          </label>
          <label>Severidade
            <select name="severity">
              {''.join(severity_options)}
            </select>
          </label>
          <label>Correcao
            <select name="fix">
              {''.join(fix_options)}
            </select>
          </label>
          <button class="action primary" type="submit">Aplicar</button>
          <span class="table-count">{len(visible_rows)} de {len(rows)} CVEs exibidas</span>
        </form>
        <table>
          <thead>
            <tr><th>Sev.</th><th>Container</th><th>Contexto</th><th>CVE</th><th>Pacote</th><th>Instalada</th><th>Corrigida</th><th>Resumo</th><th>Acao recomendada</th></tr>
          </thead>
          <tbody>{''.join(body_rows)}</tbody>
        </table>
        """,
    )


def render_score_factors_table(rows, selected_container="__all__"):
    if not rows:
        return section("Composicao do score", "", '<div class="empty">Nenhum fator de score encontrado.</div>')

    selected_container = selected_container or "__all__"
    keys = []
    seen = set()
    for item in rows:
        key = item.get("container_key") or "__unknown__"
        if key in seen:
            continue
        seen.add(key)
        keys.append({
            "key": key,
            "label": f"{item.get('context') or 'sem contexto'} / {item.get('container_name') or 'sem container'}",
            "image": item.get("image") or "",
        })
    valid_keys = {item["key"] for item in keys}
    if selected_container != "__all__" and selected_container not in valid_keys:
        selected_container = "__all__"

    visible_rows = [
        item for item in rows
        if selected_container == "__all__" or item.get("container_key") == selected_container
    ][:120]

    options = [f'<option value="__all__" {"selected" if selected_container == "__all__" else ""}>Todos os containers</option>']
    options.extend(
        f'<option value="{esc(item["key"])}" {"selected" if item["key"] == selected_container else ""}>{esc(item["label"])} - {esc(item["image"])}</option>'
        for item in keys
    )

    body_rows = []
    for item in visible_rows:
        body_rows.append(
            "<tr>"
            f'<td><span class="cell-strong">{esc(item.get("container_name"))}</span><span class="cell-sub">{esc(item.get("image"))}</span></td>'
            f"<td>{esc(item.get('context'))}</td>"
            f"<td>{esc(item.get('score'))}</td>"
            f"<td>{esc(item.get('points'))}</td>"
            f"<td>{severity_badge(item.get('severity'))}</td>"
            f"<td>{esc(item.get('type'))}</td>"
            f'<td><span class="cell-sub">{esc(item.get("evidence"))}</span></td>'
            "</tr>"
        )

    return section(
        "Composicao do score",
        "Mostra quais achados somaram pontos para a nota de risco do container. A nota final tem teto em 100.",
        f"""
        <form class="table-tools" method="get" action="/reports/technical">
          <label>Filtrar por container
            <select name="cve_container">
              {''.join(options)}
            </select>
          </label>
          <button class="action primary" type="submit">Aplicar</button>
          <span class="table-count">{len(visible_rows)} fatores exibidos</span>
        </form>
        <table>
          <thead>
            <tr><th>Container</th><th>Contexto</th><th>Score final</th><th>Pontos</th><th>Sev.</th><th>Tipo</th><th>Evidencia</th></tr>
          </thead>
          <tbody>{''.join(body_rows)}</tbody>
        </table>
        """,
    )


def svg_donut_chart(counts, order, subtitle="total"):
    values = [(key, int(counts.get(key, 0) or 0)) for key in order]
    total = sum(value for _, value in values)
    size = 210
    center = 105
    radius = 72
    circumference = 2 * 3.141592653589793 * radius
    colors = {
        "CRITICAL": "#ef6a73",
        "HIGH": "#f59e6b",
        "MEDIUM": "#f4d27a",
        "LOW": "#3dd3c5",
        "UNKNOWN": "#6fa8ff",
    }
    segments = []
    if total <= 0:
        values = [(key, 0) for key in order]
        total = 0
    offset = 0.0
    for key, value in values:
        if total > 0 and value > 0:
            length = (value / total) * circumference
            segments.append(
                f'<circle cx="{center}" cy="{center}" r="{radius}" fill="none" stroke="{colors.get(key, "#6fa8ff")}" '
                f'stroke-width="18" stroke-linecap="round" stroke-dasharray="{length:.2f} {circumference - length:.2f}" '
                f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {center} {center})"></circle>'
            )
            offset += length
    if not segments:
        segments.append(
            f'<circle cx="{center}" cy="{center}" r="{radius}" fill="none" stroke="#2f3744" stroke-width="18"></circle>'
        )
    legend = "".join(
        f'<div class="chart-legend-item"><span class="swatch" style="background:{colors.get(key, "#6fa8ff")}"></span>'
        f'<span>{esc(key)} <strong>{esc(value)}</strong></span></div>'
        for key, value in values
    )
    return f"""
    <div class="chart-shell">
      <svg viewBox="0 0 {size} {size}" class="chart-svg donut">
        <circle cx="{center}" cy="{center}" r="{radius}" fill="none" stroke="#283042" stroke-width="18"></circle>
        {''.join(segments)}
        <text x="{center}" y="{center - 2}" text-anchor="middle" class="chart-main-value">{esc(total)}</text>
        <text x="{center}" y="{center + 18}" text-anchor="middle" class="chart-main-label">{esc(subtitle)}</text>
      </svg>
      <div class="chart-legend">{legend}</div>
    </div>
    """


def svg_bar_chart(items, title_key, value_key, color="#6fa8ff", limit=6):
    rows = items[:limit]
    if not rows:
        rows = [{title_key: "sem dados", value_key: 0}]
    width = 640
    height = 240
    left = 24
    top = 22
    bottom = 24
    chart_h = height - top - bottom
    max_value = max([int(row.get(value_key, 0) or 0) for row in rows] or [1]) or 1
    if max_value <= 0:
        max_value = 1
    row_h = chart_h / max(len(rows), 1)
    bars = []
    for idx, row in enumerate(rows):
        value = int(row.get(value_key, 0) or 0)
        bar_w = max(10, round((max(value, 0) / max_value) * (width - 180)))
        y = top + (idx * row_h) + (row_h * 0.24)
        bars.append(f'<text x="{left}" y="{y + 14:.1f}" class="chart-axis">{esc(row.get(title_key))}</text>')
        bars.append(f'<rect x="220" y="{y:.1f}" width="{bar_w}" height="{max(8, row_h * 0.38):.1f}" rx="6" fill="{color}"></rect>')
        bars.append(f'<text x="{220 + bar_w + 10}" y="{y + 14:.1f}" class="chart-value">{esc(value)}</text>')
    return f"""
    <div class="chart-shell">
      <svg viewBox="0 0 {width} {height}" class="chart-svg bars">
        <line x1="220" y1="{top}" x2="220" y2="{height - bottom}" class="chart-gridline"></line>
        {''.join(bars)}
      </svg>
    </div>
    """


def render_chart_grid(vulns, top_rows, context_rows):
    severity_counts = vulns.get("severity_counts") or {}
    severity_items = [{"severity": key, "count": value} for key, value in severity_counts.items()]
    top_items = [
        {"label": f"{item.get('container_name')} ({item.get('host_name')})", "score": item.get("score", 0)}
        for item in top_rows[:6]
    ]
    context_items = [
        {"label": item.get("context"), "score": item.get("score_max", 0)}
        for item in context_rows[:6]
    ]
    return section(
        "Visuais",
        "Os graficos ficam visiveis mesmo quando o inventario ainda esta vazio.",
        f"""
        <section class="grid two" style="padding:0; margin:0;">
          <div class="panel" style="margin:0;">
            <h2>CVEs por severidade</h2>
            {svg_donut_chart(severity_counts, ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"], "total")}
          </div>
          <div class="panel" style="margin:0;">
            <h2>Top containers por risco</h2>
            {svg_bar_chart(top_items, "label", "score", "#6fa8ff")}
          </div>
        </section>
        <div class="panel" style="margin-top:16px;">
          <h2>Contextos prioritarios</h2>
          {svg_bar_chart(context_items, "label", "score", "#3dd3c5")}
        </div>
        """
    )


def render_summary_table(summary, dependency_track, alerts, trivy, vulns):
    rows = [
        ("Hosts", f"{summary.get('hosts_success', 0)}/{summary.get('hosts_total', 0)}"),
        ("Contextos", f"{summary.get('contexts_success', 0)}/{summary.get('contexts_total', 0)}"),
        ("Containers", summary.get("containers_total", 0)),
        ("Imagens", summary.get("images_total", 0)),
        ("Achados", summary.get("findings_total", 0)),
        ("Vulnerabilidades", vulns.get("total", 0)),
        ("Vulnerabilidades DT", ((dependency_track.get("analysis_totals") or {}).get("dtrack_vulnerabilities", 0))),
        ("Alertas ativos", ((alerts.get("totals") or {}).get("active", 0))),
    ]
    rows_html = "".join(f"<tr><th>{esc(label)}</th><td>{esc(value)}</td></tr>" for label, value in rows)
    return section("Resumo", "Estrutura principal preenchida quando os dados chegarem.", f"<table>{rows_html}</table>")


def render_links_panel():
    return section(
        "Acessos",
        "Os links abaixo existem mesmo antes do primeiro scan.",
        f"""
        <div class="status-strip">
          {link_tile("Relatorio gerencial", "/reports/executive")}
          {link_tile("Relatorio tecnico", "/reports/technical")}
          {link_tile("JSON", "/api/status")}
          {link_tile("Metrics", "/metrics")}
          {link_tile("Dependency-Track", f'http://{esc(PUBLIC_HOST)}:8080')}
        </div>
        """
    )


def render_table_panel(title, headers, items, row_builder, empty_message):
    if not items:
        return section(title, "", f'<div class="empty">{esc(empty_message)}</div>')
    head = "".join(f"<th>{esc(header)}</th>" for header in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row_builder(item)) + "</tr>" for item in items)
    return section(title, "", f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>")


def section(title, subtitle, content):
    subtitle_html = f'<p class="subtext">{esc(subtitle)}</p>' if subtitle else ""
    return f'<section class="section"><h2>{esc(title)}</h2>{subtitle_html}{content}</section>'


def pill(label, value):
    return f'<div class="pill"><span>{esc(label)}</span><strong>{esc(value)}</strong></div>'


def link_tile(label, href):
    return f'<a class="action" href="{esc(href)}">{esc(label)}</a>'


def empty_panel(title, message):
    return section(title, "", f'<div class="empty">{esc(message)}</div>')


def render_status_chips(status):
    dependency_track = status.get("dependency_track") or {}
    alerts = status.get("alerts") or {}
    trivy = status.get("trivy") or {}
    summary = status.get("summary") or {}
    return [
        ("Login", "ativo", "good"),
        ("Inventario", status.get("inventory_status") or "aguardando", "neutral"),
        ("DT", dependency_track.get("status") or "aguardando", "neutral"),
        ("Trivy", trivy.get("images_total") or 0, "warn" if (trivy.get("images_total") or 0) else "neutral"),
        ("Alertas", alerts.get("status") or "aguardando", "danger" if (alerts.get("totals") or {}).get("active") else "neutral"),
        ("Dados", "prontos" if summary.get("containers_total") else "sem scan", "good" if summary.get("containers_total") else "warn"),
    ]


def build_report_chips(status, scan_state=None):
    dependency_track = status.get("dependency_track") or {}
    alerts = status.get("alerts") or {}
    summary = status.get("summary") or {}
    scan_state = scan_state or {}
    return [
        ("Relatorio", "aberto", "good"),
        ("DT", dependency_track.get("analysis_status") or "aguardando", "neutral"),
        ("Containers", summary.get("containers_total", 0), "neutral"),
        ("Alertas", (alerts.get("totals") or {}).get("active", 0), "danger" if (alerts.get("totals") or {}).get("active") else "neutral"),
        ("Scan manual", scan_state.get("state") or "inativo", "good" if scan_state.get("state") == "success" else "warn" if scan_state.get("state") == "running" else "neutral"),
    ]


def render_manual_scan_panel(scan_state):
    state = scan_state.get("state") or "inativo"
    started_at = scan_state.get("started_at") or "aguardando"
    finished_at = scan_state.get("finished_at") or "aguardando"
    note = scan_state.get("note") or "Nenhum scan manual disparado ainda."
    button_label = "Executando..." if state == "running" else "Executar scan manual"
    button_disabled = "disabled" if state == "running" else ""
    return section(
        "Scan manual",
        "Dispare um ciclo completo sem esperar o timer do systemd.",
        f"""
        <div class="status-strip" style="margin-bottom: 14px;">
          {pill("Estado", state)}
          {pill("Iniciado", started_at)}
          {pill("Finalizado", finished_at)}
          {pill("Detalhe", note)}
        </div>
        <form method="post" action="/scan/manual">
          <button class="action primary" type="submit" {button_disabled}>{esc(button_label)}</button>
        </form>
        """
    )



def select_option(value, current, label):
    return f'<option value="{esc(value)}" {"selected" if str(value) == str(current) else ""}>{esc(label)}</option>'


def render_settings_page(query=None):
    status = status_payload()
    schedule = load_scan_schedule()
    code_scan_config = load_code_scan_config()
    query = query or {}
    notice = ""
    if query.get("schedule", [""])[0] == "saved":
        notice = '<div class="empty">Agenda salva e timer systemd atualizado.</div>'
    elif query.get("schedule", [""])[0] == "failed":
        notice = '<div class="empty">Nao foi possivel aplicar a agenda. Veja a mensagem abaixo.</div>'
    elif query.get("schedule", [""])[0] == "invalid":
        notice = '<div class="empty">Valores invalidos. Ajuste hora, minuto e frequencia.</div>'
    timer_lines = timer_status_lines()
    timer_html = "<br>".join(esc(line) for line in timer_lines[:8]) or "sem status do timer"
    weekday_options = "".join(select_option(key, schedule.get("weekday"), label) for key, label in WEEKDAY_LABELS.items())
    frequency_options = "".join([
        select_option("daily", schedule.get("frequency"), "Todos os dias"),
        select_option("weekly", schedule.get("frequency"), "Semanal"),
    ])
    enabled_checked = "checked" if schedule.get("enabled", True) else ""
    body = [
        section(
            "Agenda de scans",
            "Configure quando o ciclo completo deve ser executado pelo systemd timer.",
            f"""
            {notice}
            <div class="status-strip" style="margin-bottom: 14px;">
              {pill("Agenda atual", schedule_label(schedule))}
              {pill("OnCalendar", schedule.get("on_calendar"))}
              {pill("Timer", "ativo" if schedule.get("enabled", True) else "desativado")}
              {pill("Ultima aplicacao", schedule.get("last_apply_status") or "-")}
            </div>
            <form method="post" action="/settings/schedule">
              <div class="table-tools">
                <label>Ativo
                  <input type="checkbox" name="enabled" {enabled_checked}>
                </label>
                <label>Frequencia
                  <select name="frequency">{frequency_options}</select>
                </label>
                <label>Dia da semana
                  <select name="weekday">{weekday_options}</select>
                </label>
                <label>Hora
                  <input type="number" name="hour" min="0" max="23" value="{esc(schedule.get("hour"))}">
                </label>
                <label>Minuto
                  <input type="number" name="minute" min="0" max="59" value="{esc(schedule.get("minute"))}">
                </label>
                <label>Atraso aleatorio min
                  <input type="number" name="randomized_delay_minutes" min="0" max="120" value="{esc(schedule.get("randomized_delay_minutes", 0))}">
                </label>
                <button class="action primary" type="submit">Salvar agenda</button>
              </div>
            </form>
            """,
        ),
        section(
            "Timer systemd",
            "Estado retornado pelo systemd para o timer de scan.",
            f'<div class="empty"><span class="cell-sub">{timer_html}</span></div>',
        ),
        render_code_scan_config_panel(code_scan_config, query),
        render_latest_scan_log_panel(),
        render_manual_scan_panel(manual_scan_state()),
    ]
    return render_shell(
        title="Configuracao",
        eyebrow="Configuracao operacional",
        subtitle="Agenda de scans e acionamento manual do pipeline backend.",
        cards=[
            ("Agenda", schedule_label(schedule)),
            ("OnCalendar", schedule.get("on_calendar")),
            ("Timer", "ativo" if schedule.get("enabled", True) else "desativado"),
            ("Run atual", status.get("run_id") or "aguardando"),
            ("Ultima aplicacao", schedule.get("last_apply_status") or "-"),
            ("Mensagem", schedule.get("last_apply_message") or "-"),
            ("Exclusoes SAST", len(code_scan_config.get("exclude_dirs") or [])),
        ],
        sections={"settings": "active"},
        status_chips=render_status_chips(status),
        body_blocks=body,
    )


def render_status_chip(label, value, tone):
    return f'<div class="chip {esc(tone)}"><div class="chip-label">{esc(label)}</div><div class="chip-value">{esc(value)}</div></div>'


def render_error_page(code, title, detail):
    return render_shell(
        title=f"{code} - {title}",
        eyebrow="Erro",
        subtitle=detail,
        cards=[
            ("Codigo", code),
            ("Estado", "indisponivel"),
            ("Painel", "carregado"),
            ("Login", "ativo"),
            ("Relatorios", "estruturados"),
            ("Dados", "aguardando"),
        ],
        sections={"dashboard": "", "executive": "", "technical": ""},
        body_blocks=[
            empty_panel(
                title,
                detail,
            ),
        ],
    )


def render_report_body(kind_key, status, source_name):
    summary = status.get("summary") or {}
    dependency_track = status.get("dependency_track") or {}
    alerts = status.get("alerts") or {}
    trivy = status.get("trivy") or {}
    vulns = status.get("vulnerability_summary") or {}
    rows = [
        ("Fonte", source_name),
        ("Run ID", status.get("run_id") or "aguardando"),
        ("Inventario", status.get("inventory_status") or "aguardando"),
        ("Dependency-Track", dependency_track.get("status") or "aguardando"),
        ("Analise DT", dependency_track.get("analysis_status") or "aguardando"),
        ("Alertas", alerts.get("status") or "aguardando"),
    ]
    return [
        section(
            "Metadados",
            "Campos fixos do relatório. Quando não houver dados, o painel fica em estado vazio ao invés de quebrar.",
            f"<table>{''.join(f'<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>' for k, v in rows)}</table>",
        ),
        render_summary_table(summary, dependency_track, alerts, trivy, vulns),
        render_table_panel(
            "Top riscos",
            ["Score", "Classe", "Contexto", "Host", "Container", "Imagem"],
            status.get("top_risks") or [],
            lambda item: [
                esc(item.get("score")),
                esc(item.get("classification")),
                esc(item.get("context")),
                esc(item.get("host_name")),
                esc(item.get("container_name")),
                esc(item.get("image")),
            ],
            empty_message="Nenhum risco calculado ainda.",
        ),
        render_table_panel(
            "Contextos prioritarios",
            ["Contexto", "Containers", "Score Max", "Score Medio", "Achados", "Criticos", "Altos"],
            status.get("context_summary") or [],
            lambda item: [
                esc(item.get("context")),
                esc(item.get("containers")),
                esc(item.get("score_max")),
                esc(item.get("score_avg")),
                esc(item.get("findings")),
                esc(item.get("critical_containers")),
                esc(item.get("high_containers")),
            ],
            empty_message="Nenhum contexto calculado ainda.",
        ),
    ]


def render_login(error="", next_path="/"):
    message = f"<p class=\"error\">{esc(error)}</p>" if error else ""
    return f"""<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <title>Container Security Monitor - Login</title>
  <style>
    :root {{
      --bg: #e9eff7;
      --surface: #ffffff;
      --border: #cfd9e6;
      --ink: #102033;
      --muted: #5f6d7d;
      --accent: #0f5fa8;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(15, 95, 168, 0.16), transparent 28%),
        radial-gradient(circle at bottom right, rgba(17, 122, 116, 0.14), transparent 24%),
        linear-gradient(180deg, #f7faff 0%, var(--bg) 100%);
    }}
    .panel {{
      width: min(440px, calc(100vw - 32px));
      background: rgba(255, 255, 255, 0.92);
      border: 1px solid var(--border);
      padding: 30px;
      border-radius: 22px;
      box-shadow: 0 18px 42px rgba(16, 32, 51, 0.10);
      backdrop-filter: blur(10px);
    }}
    h1 {{ margin-top: 0; color: var(--ink); font-size: 26px; }}
    p {{ color: var(--muted); line-height: 1.5; }}
    label {{ display: block; margin: 16px 0 6px; font-weight: 700; }}
    input {{
      width: 100%;
      box-sizing: border-box;
      padding: 11px 12px;
      border: 1px solid var(--border);
      border-radius: 12px;
      background: #fbfdff;
      color: var(--ink);
    }}
    input:focus {{
      outline: 2px solid rgba(15, 95, 168, 0.18);
      border-color: rgba(15, 95, 168, 0.45);
    }}
    button {{
      margin-top: 18px;
      width: 100%;
      padding: 12px 14px;
      border: 0;
      border-radius: 12px;
      background: linear-gradient(180deg, var(--accent) 0%, #0b4e8a 100%);
      color: #fff;
      cursor: pointer;
      font-weight: 700;
      box-shadow: 0 10px 22px rgba(15, 95, 168, 0.18);
    }}
    .hint {{ margin-top: 16px; color: var(--muted); font-size: 13px; }}
    .error {{
      padding: 10px 12px;
      background: rgba(180, 35, 24, 0.08);
      border: 1px solid rgba(180, 35, 24, 0.18);
      color: #9f1d14;
      border-radius: 12px;
    }}
  </style>
</head>
<body>
  <form class="panel" method="post" action="/login">
    <h1>Container Security Monitor</h1>
    <p>Login de acesso ao painel de relatórios.</p>
    {message}
    <input type="hidden" name="next" value="{esc(next_path)}">
    <label for="username">Usuário</label>
    <input id="username" name="username" autocomplete="username" required>
    <label for="password">Senha</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required>
    <button type="submit">Entrar</button>
    <div class="hint">Se ainda não houver dados, a tela entra vazia após autenticação.</div>
  </form>
</body>
</html>
"""


def main():
    server = ThreadingHTTPServer((BIND, PORT), Handler)
    if not (AUTH_TOKEN_VALUE or (AUTH_USER and AUTH_PASSWORD_VALUE)):
        print("warning: status server authentication is disabled")
    print(f"serving Container Security Monitor on http://{BIND}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
