#!/usr/bin/env python3
"""
secretscan_llm.py
Pipeline híbrido: ejecuta el escáner determinista y valida hallazgos con un LLM
(OpenAI/Azure/OpenAI-compatible como Ollama) para reducir falsos positivos.

Uso:
  python3 secretscan_llm.py scan .
  python3 secretscan_llm.py scan . --auto-ignore-llm
  python3 secretscan_llm.py scan . --rules "only_new=true,min=medium"

Requisitos:
  - secretscan.py en el mismo repo
  - llm_validator.py accesible en el mismo directorio o PYTHONPATH
  - Variables de entorno del proveedor LLM (ver README)
Salida:
  - Exit 1 si quedan secretos NEW que el LLM confirma como secretos.
  - Cache de decisiones: .secrets-llm-cache.json
"""

import os
import sys
import json
import subprocess
import shlex
import argparse

# Asegura que el directorio del script esté en sys.path para importar llm_validator.py
HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from llm_validator import classify_secret, LLMError  # noqa: E402

IGNORE_FILE = ".secrets-ignore.json"
LLM_CACHE = ".secrets-llm-cache.json"


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def run_base_scan(repo):
    cmd = f"python3 secretscan.py scan {shlex.quote(repo)} --json"
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    stdout = p.stdout.strip()
    try:
        return json.loads(stdout)
    except Exception:
        print("[ERROR] Salida no-JSON del escáner determinista:", file=sys.stderr)
        print(stdout[:4000], file=sys.stderr)
        sys.exit(2)


def read_context(repo_root, file_rel, line_no, radius=4):
    path = os.path.join(repo_root, file_rel)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except Exception:
        return ""
    i = max(0, line_no - 1 - radius)
    j = min(len(lines), line_no - 1 + radius + 1)
    snippet = "".join(lines[i:j])
    return f"--- FILE: {file_rel} (lines {i+1}-{j}) ---\n{snippet}\n"


def main():
    ap = argparse.ArgumentParser(description="Escaneo híbrido con LLM")
    sub = ap.add_subparsers(dest="cmd")

    sc = sub.add_parser("scan", help="Escanear ruta con validación LLM")
    sc.add_argument("path", help="Ruta del repo a analizar")
    sc.add_argument(
        "--auto-ignore-llm",
        dest="auto_ignore_llm",
        action="store_true",
        help="Añade a .secrets-ignore.json huellas clasificadas por LLM como NO secretas"
    )
    sc.add_argument(
        "--rules",
        default="",
        help='Opciones "k=v" separadas por coma. Ej.: "only_new=true,min=medium"'
    )

    args = ap.parse_args()

    if args.cmd != "scan":
        ap.print_help()
        sys.exit(0)

    repo = os.path.abspath(args.path)

    # Parse flags de reglas
    opts = {}
    if args.rules:
        for kv in filter(None, [x.strip() for x in args.rules.split(",")]):
            if "=" in kv:
                k, v = kv.split("=", 1)
                opts[k.strip()] = v.strip()

    only_new = opts.get("only_new", "true").lower() == "true"
    min_conf = opts.get("min", "low").lower()
    order = {"low": 0, "medium": 1, "high": 2}

    # Cargar ignorados y cache
    base = load_json(IGNORE_FILE, {"ignored": []})
    ignored = set(base.get("ignored", []))
    cache = load_json(LLM_CACHE, {})  # fingerprint -> decision dict

    # 1) Escaneo determinista
    data = run_base_scan(repo)
    findings = data.get("findings", [])

    def consider(f):
        if only_new and f.get("status") != "new":
            return False
        return order.get(f.get("confidence", "low").lower(), 0) >= order.get(min_conf, 0)

    # 2) Candidatos para LLM
    candidates = [f for f in findings if consider(f) and f["fingerprint"] not in ignored]

    # 3) Llamadas al LLM
    decisions = {}
    for f in candidates:
        fp = f["fingerprint"]
        if fp in cache:
            decisions[fp] = cache[fp]
            continue

        ctx = read_context(repo, f["file"], f["line"], 4)
        prompt = f"""Clasifica si esto es un secreto expuesto en código.

Regla: {f['rule']}
Coincidencia (redactada): {f['redacted']}
Archivo:Línea: {f['file']}:{f['line']}
Confianza heurística: {f.get('confidence','unknown')}

Contexto:
{ctx}

Responde SOLO JSON con: is_secret (bool), severity (low|medium|high|critical),
rationale (string), suggested_fix (string). Si dudas, is_secret=true.
"""
        try:
            dec = classify_secret(prompt)
        except LLMError as e:
            print(f"[LLM ERROR] {e}", file=sys.stderr)
            dec = {
                "is_secret": True,
                "severity": "high",
                "rationale": "LLM error; fail-safe.",
                "suggested_fix": "Retirar/rotar credencial."
            }
        decisions[fp] = dec
        cache[fp] = dec

    save_json(LLM_CACHE, cache)

    # 4) Auto-ignore opcional
    auto_ignored = []
    if getattr(args, "auto_ignore_llm", False):
        for fp, dec in decisions.items():
            if not dec.get("is_secret", True):
                ignored.add(fp)
                auto_ignored.append(fp)
        save_json(IGNORE_FILE, {"ignored": sorted(list(ignored))})

    # 5) Evaluar fallos: secretos NEW que (LLM==secreto) y no ignorados
    failing = []
    for f in findings:
        if f["status"] != "new":
            continue
        fp = f["fingerprint"]
        dec = decisions.get(fp, cache.get(fp))
        is_secret = True if dec is None else bool(dec.get("is_secret", True))
        if is_secret and fp not in ignored:
            failing.append((f, dec))

    # Resumen
    def short_dec(dec):
        if not dec:
            return "no-eval"
        return f"{'SECRET' if dec.get('is_secret', True) else 'benigno'} / sev={dec.get('severity','?')}"

    print("\n=== Resumen LLM ===")
    if decisions:
        for fp, dec in decisions.items():
            print(f"- {fp}: {short_dec(dec)}")
    else:
        print("- Sin candidatos para validación LLM.")

    if auto_ignored:
        print(f"\nAuto-ignorados por LLM ({len(auto_ignored)}): {', '.join(auto_ignored)}")

    if failing:
        print(f"\n❌ Siguen secretos 'new' tras validación LLM ({len(failing)}):")
        for f, dec in failing:
            print(f"  - {f['file']}:{f['line']} [{f['rule']}] ({f['fingerprint']}) -> {short_dec(dec)}")
        sys.exit(1)

    print("\n✅ No quedan secretos 'new' tras validación LLM.")
    sys.exit(0)


if __name__ == "__main__":
    main()
