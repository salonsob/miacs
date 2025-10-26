#!/usr/bin/env python3
import os, requests, re, json
DEFAULT_MODEL = os.getenv("LLM_MODEL", "gpt-4o-mini")
DEFAULT_PROVIDER = os.getenv("LLM_PROVIDER", "openai")
class LLMError(Exception): pass
def _headers(api_key: str): return {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
def chat_completion(messages, model=None, temperature=0.0, provider=None):
    api_key=os.getenv("LLM_API_KEY"); 
    if not api_key: raise LLMError("Falta LLM_API_KEY")
    provider=provider or os.getenv("LLM_PROVIDER", DEFAULT_PROVIDER)
    model=model or os.getenv("LLM_MODEL", DEFAULT_MODEL)
    if provider=="openai":
        base=os.getenv("LLM_BASE_URL","https://api.openai.com/v1")
        url=f"{base}/chat/completions"; payload={"model":model,"messages":messages,"temperature":temperature}
        r=requests.post(url, headers=_headers(api_key), json=payload, timeout=60)
    elif provider=="azure":
        endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"); api_ver=os.getenv("AZURE_OPENAI_API_VERSION","2024-10-21")
        if not endpoint: raise LLMError("Falta AZURE_OPENAI_ENDPOINT")
        url=f"{endpoint}/openai/deployments/{model}/chat/completions?api-version={api_ver}"
        r=requests.post(url, headers=_headers(api_key), json={"messages":messages,"temperature":temperature}, timeout=60)
    else:
        base=os.getenv("LLM_BASE_URL"); 
        if not base: raise LLMError("Falta LLM_BASE_URL para provider=compatible")
        url=f"{base.rstrip('/')}/chat/completions"; payload={"model":model,"messages":messages,"temperature":temperature}
        r=requests.post(url, headers=_headers(api_key), json=payload, timeout=60)
    if r.status_code>=300: raise LLMError(f"HTTP {r.status_code}: {r.text[:400]}")
    return r.json()
def classify_secret(prompt: str, model: str=None, provider: str=None) -> dict:
    sys_msg={"role":"system","content":"Eres analista de seguridad. Devuelve SOLO JSON: {is_secret: bool, severity: low|medium|high|critical, rationale: string, suggested_fix: string}. Si dudas, is_secret=true."}
    user_msg={"role":"user","content":prompt}
    data=chat_completion([sys_msg,user_msg], model=model, provider=provider, temperature=0.0)
    try:
        txt=data["choices"][0]["message"]["content"]
    except Exception as e:
        raise LLMError(f"Respuesta inesperada: {data}") from e
    m=re.search(r"\{.*\}", txt, re.S)
    if not m: return {"is_secret": True, "severity":"high","rationale":"No JSON parseable; fail-safe.","suggested_fix":"Retirar/rotar credencial."}
    try:
        obj=json.loads(m.group(0))
        obj["is_secret"]=bool(obj.get("is_secret", True))
        obj["severity"]=str(obj.get("severity","high")).lower()
        obj["rationale"]=str(obj.get("rationale",""))[:2000]
        obj["suggested_fix"]=str(obj.get("suggested_fix",""))[:1000]
        return obj
    except Exception:
        return {"is_secret": True, "severity":"high","rationale":"JSON inválido; fail-safe.","suggested_fix":"Retirar/rotar credencial."}
