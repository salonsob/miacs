#!/usr/bin/env python3
"""
Secret Scanner (Python)
- Escanea recursivamente el repo buscando secretos en texto plano.
- Reglas: patrones conocidos + heurística de asignaciones de credenciales + entropía.
- Soporta lista de falsos positivos (.secrets-ignore.json) con huellas (fingerprints).
- Salidas: CLI, JSON (--json), informe Markdown (--md-report OUT.md).
- Comandos para gestionar ignorados: --ignore FINGERPRINT (añade a .secrets-ignore.json).

Uso básico:
  python secretscan.py scan .
  python secretscan.py scan . --json
  python secretscan.py scan . --md-report report.md
  python secretscan.py --ignore <fingerprint>

Por diseño, nunca imprime el valor completo del secreto. Redacta el centro de la coincidencia.
"""
import argparse, os, re, sys, json, hashlib, base64, math, pathlib, datetime

IGNORE_FILE = ".secrets-ignore.json"
DEFAULT_EXCLUDES = {".git", ".venv", "venv", "node_modules", "__pycache__", ".idea", ".vscode", "dist", "build"}

# Reglas de patrones comunes
RULES = [
    # Claves privadas
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|PGP|DSA) PRIVATE KEY-----")),
    # AWS Access Key ID
    ("AWS_ACCESS_KEY_ID", re.compile(r"(?<![A-Z0-9])[A-Z0-9]{4}?(?:AKIA|ASIA)[A-Z0-9]{12}(?![A-Z0-9])")),
    # AWS Secret (heurística simple, mejor usar validadores externos)
    ("AWS_SECRET_ACCESS_KEY", re.compile(r"(?i)aws(.{0,20})?(secret|sk|key)(.{0,20})?[:=]\s*['\"][A-Za-z0-9/+=]{30,}['\"]")),
    # GitHub token
    ("GITHUB_TOKEN", re.compile(r"(?i)(ghp|github_pat)_[A-Za-z0-9_]{20,}")),
    # Slack token
    ("SLACK_TOKEN", re.compile(r"(xox[aboprs]-[A-Za-z0-9-]{10,})")),
    # Stripe live key
    ("STRIPE_LIVE", re.compile(r"(?i)(sk_live|rk_live)_[A-Za-z0-9]{20,}")),
    # Twilio auth token (heurístico)
    ("TWILIO", re.compile(r"(?i)twilio(.{0,20})?(secret|token|auth)(.{0,20})?[:=]\s*['\"][A-Za-z0-9]{20,}['\"]")),
    # Contraseñas / API keys en asignaciones (heurística)
    ("GENERIC_PASSWORD_ASSIGN", re.compile(r"(?i)(password|passwd|pwd|secret|api[_-]?key|token)\s*=\s*['\"][^'\"]{6,}['\"]")),
    # Cadenas de conexión con user:pass@
    ("URL_CREDENTIALS", re.compile(r"[a-z]+:\/\/[^\/\s:]+:[^@\/\s]+@")),
]

BINARY_MAGIC = (b"\x00",)

def load_ignored():
    try:
        with open(IGNORE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return set(data.get("ignored", []))
    except FileNotFoundError:
        return set()

def save_ignored(ignored: set):
    data = {"ignored": sorted(list(ignored))}
    with open(IGNORE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def is_binary(path):
    try:
        with open(path, "rb") as f:
            chunk = f.read(1024)
            return any(b in chunk for b in BINARY_MAGIC)
    except Exception:
        return False

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    h = 0.0
    l = len(s)
    for c in freq.values():
        p = c / l
        h -= p * math.log2(p)
    return h

def redact(s: str) -> str:
    if len(s) <= 6:
        return "***"
    return s[:3] + "…" + s[-3:]

def fingerprint(file_path: str, line_no: int, rule_id: str, matched_text: str) -> str:
    hasher = hashlib.sha256()
    hasher.update((file_path + ":" + str(line_no) + ":" + rule_id + ":" + matched_text[:16]).encode("utf-8"))
    return hasher.hexdigest()[:16]

def scan_path(path: str, excluded: set):
    ignored = load_ignored()
    findings = []
    for root, dirs, files in os.walk(path):
        # filter dirs
        dirs[:] = [d for d in dirs if d not in excluded]
        for name in files:
            fpath = os.path.join(root, name)
            # saltar ficheros ignorados por nombre
            if any(part in excluded for part in pathlib.Path(fpath).parts):
                continue
            # límites de tamaño
            try:
                if os.path.getsize(fpath) > 2 * 1024 * 1024:
                    continue
            except OSError:
                continue
            # binarios
            if is_binary(fpath):
                continue
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                    for i, line in enumerate(fh, start=1):
                        # patrones clásicos
                        for rid, rx in RULES:
                            for m in rx.finditer(line):
                                val = m.group(0)
                                fp = fingerprint(fpath, i, rid, val)
                                status = "ignored" if fp in ignored else "new"
                                findings.append({
                                    "file": os.path.relpath(fpath, path),
                                    "line": i,
                                    "rule": rid,
                                    "redacted": redact(val),
                                    "fingerprint": fp,
                                    "status": status,
                                    "confidence": "high" if rid in {"PRIVATE_KEY","AWS_ACCESS_KEY_ID","GITHUB_TOKEN","SLACK_TOKEN","STRIPE_LIVE","URL_CREDENTIALS"} else "medium",
                                })
                        # heurística de alta entropía para literales largos (solo letras/números/+/_/=)
                        for m in re.finditer(r"['\"]([A-Za-z0-9/_+=-]{24,})['\"]", line):
                            candidate = m.group(1)
                            ent = shannon_entropy(candidate)
                            if ent >= 3.5:
                                rid = "HIGH_ENTROPY_STRING"
                                fp = fingerprint(fpath, i, rid, candidate)
                                status = "ignored" if fp in ignored else "new"
                                findings.append({
                                    "file": os.path.relpath(fpath, path),
                                    "line": i,
                                    "rule": rid,
                                    "redacted": redact(candidate),
                                    "fingerprint": fp,
                                    "status": status,
                                    "confidence": "low",
                                })
            except Exception as e:
                print(f"[WARN] No se pudo leer {fpath}: {e}", file=sys.stderr)
    return findings

def print_table(findings):
    if not findings:
        print("✅ Sin secretos encontrados.")
        return
    print("⚠️  Posibles secretos encontrados:\n")
    print(f"{'STATUS':8} {'RULE':22} {'FILE:LINE':40} {'REDACTED'}")
    print("-"*100)
    for f in findings:
        where = f"{f['file']}:{f['line']}"
        print(f"{f['status']:<8} {f['rule']:<22} {where:<40} {f['redacted']}  ({f['fingerprint']})")

def write_md_report(findings, out_path):
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    total = len(findings)
    new = sum(1 for f in findings if f["status"] == "new")
    ignored = sum(1 for f in findings if f["status"] == "ignored")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(f"# Informe de escaneo de secretos\n\n")
        f.write(f"- Fecha/hora (UTC): **{ts}**\n")
        f.write(f"- Total hallazgos: **{total}** — Nuevos: **{new}**, Ignorados (FP): **{ignored}**\n\n")
        if findings:
            f.write("| Estado | Regla | Fichero:Línea | Coincidencia (redactada) | Huella |\n")
            f.write("|---|---|---|---|---|\n")
            for x in findings:
                where = f"{x['file']}:{x['line']}"
                f.write(f"| {x['status']} | {x['rule']} | `{where}` | `{x['redacted']}` | `{x['fingerprint']}` |\n")
        else:
            f.write("✅ Sin secretos encontrados.\n")

def main():
    ap = argparse.ArgumentParser(description="Escáner de secretos")
    sub = ap.add_subparsers(dest="cmd")

    sc = sub.add_parser("scan", help="Escanear ruta")
    sc.add_argument("path", help="Ruta a escanear (repo)")
    sc.add_argument("--json", action="store_true", help="Salida JSON")
    sc.add_argument("--md-report", help="Escribir informe Markdown en ruta")
    sc.add_argument("--exclude", action="append", default=[], help="Añadir carpetas a excluir")

    ig = sub.add_parser("ignore", help="Marcar un hallazgo como falso positivo por huella")
    ig.add_argument("fingerprint", help="Huella a ignorar (16 hex)")

    args = ap.parse_args()
    if args.cmd == "ignore":
        fp = args.fingerprint.strip()
        if not re.fullmatch(r"[0-9a-f]{16}", fp):
            print("Formato de fingerprint inválido.", file=sys.stderr)
            sys.exit(2)
        ignored = load_ignored()
        ignored.add(fp)
        save_ignored(ignored)
        print(f"Añadido a ignorados: {fp}")
        sys.exit(0)

    if args.cmd == "scan":
        path = os.path.abspath(args.path)
        excluded = set(DEFAULT_EXCLUDES) | set(args.exclude or [])
        findings = scan_path(path, excluded)
        if args.json:
            print(json.dumps({"findings": findings}, ensure_ascii=False, indent=2))
        else:
            print_table(findings)
        if args.md_report:
            write_md_report(findings, args.md_report)
        # Salida no-cero si hay hallazgos 'new' (para CI/hooks)
        has_new = any(f["status"] == "new" for f in findings)
        sys.exit(1 if has_new else 0)

    ap.print_help()
    return 0

if __name__ == "__main__":
    main()
