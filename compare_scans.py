#!/usr/bin/env python3
import argparse, json, sys, csv, os

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def main():
    ap = argparse.ArgumentParser(description="Comparar escaneo determinista vs. decisiones LLM")
    ap.add_argument("--base", required=True, help="JSON del escáner determinista (secretscan.py --json)")
    ap.add_argument("--llm-cache", required=True, help="Cache LLM (.secrets-llm-cache.json)")
    ap.add_argument("--out-md", default="compare.md", help="Salida Markdown")
    ap.add_argument("--out-csv", default="compare.csv", help="Salida CSV")
    ap.add_argument("--only-new", default="true", choices=["true","false"], help="Solo hallazgos 'new' del base")
    args = ap.parse_args()

    base = load_json(args.base)
    cache = load_json(args.llm_cache) if os.path.exists(args.llm_cache) else {}
    findings = base.get("findings", [])

    only_new = (args.only_new.lower() == "true")

    rows = []
    for f in findings:
        if only_new and f.get("status") != "new":
            continue
        fp = f["fingerprint"]
        dec = cache.get(fp)
        llm_is_secret = True if dec is None else bool(dec.get("is_secret", True))
        llm_sev = (dec or {}).get("severity", "")
        llm_rat = (dec or {}).get("rationale", "")
        rows.append({
            "file": f["file"],
            "line": f["line"],
            "rule": f["rule"],
            "fingerprint": fp,
            "det_status": f.get("status"),
            "det_confidence": f.get("confidence",""),
            "llm_is_secret": llm_is_secret,
            "llm_severity": llm_sev,
            "llm_rationale": llm_rat[:180].replace("\\n"," "),
            "redacted": f.get("redacted",""),
        })

    # Estadísticas
    total = len(rows)
    llm_benign = sum(1 for r in rows if not r["llm_is_secret"])
    llm_secret = total - llm_benign

    # CSV
    with open(args.out_csv, "w", encoding="utf-8", newline="") as fo:
        w = csv.writer(fo)
        w.writerow(["file","line","rule","fingerprint","det_status","det_confidence","llm_is_secret","llm_severity","llm_rationale","redacted"])
        for r in rows:
            w.writerow([r["file"], r["line"], r["rule"], r["fingerprint"], r["det_status"], r["det_confidence"], r["llm_is_secret"], r["llm_severity"], r["llm_rationale"], r["redacted"]])

    # Markdown
    with open(args.out_md, "w", encoding="utf-8") as fo:
        fo.write(f"# Comparativa escaneo determinista vs LLM\\n\\n")
        fo.write(f"- Total hallazgos comparados: **{total}**\\n")
        fo.write(f"- LLM clasifica como **benignos**: **{llm_benign}**\\n")
        fo.write(f"- LLM confirma como **secretos**: **{llm_secret}**\\n\\n")
        fo.write(f"**Filtrado**: only_new={only_new}\\n\\n")
        if rows:
            fo.write("| Estado(det) | Conf(det) | LLM | Sev | Fichero:Línea | Regla | Huella | Coincidencia |\\n")
            fo.write("|---|---|---|---|---|---|---|---|\\n")
            for r in rows:
                llm_txt = "SECRETO" if r["llm_is_secret"] else "benigno"
                where = f"`{r['file']}:{r['line']}`"
                fo.write(f"| {r['det_status']} | {r['det_confidence']} | {llm_txt} | {r['llm_severity']} | {where} | {r['rule']} | `{r['fingerprint']}` | `{r['redacted']}` |\\n")
        else:
            fo.write("No hay hallazgos que cumplan el filtro.\\n")

    print(f"OK: Markdown -> {args.out_md} | CSV -> {args.out_csv} | Base: {args.base} | LLM cache: {args.llm_cache}")

if __name__ == "__main__":
    main()
