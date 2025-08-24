#!/usr/bin/env python3
import json, os, logging, re, time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
from dotenv import load_dotenv

try:
    from pymisp import ExpandedPyMISP, MISPEvent, MISPObject, MISPSighting, MISPAttribute
except Exception:
    ExpandedPyMISP = None

try:
    import httpx
except Exception:
    httpx = None

try:
    from openai import OpenAI as OpenAIClient
except Exception:
    OpenAIClient = None

try:
    import anthropic
except Exception:
    anthropic = None

try:
    import google.generativeai as genai
except Exception:
    genai = None

try:
    import ollama
except Exception:
    ollama = None

load_dotenv()

MODULE_VERSION = "1.0.0"

logger = logging.getLogger("misp_ai_event_analysis")
logger.setLevel(logging.INFO)
_h = logging.StreamHandler()
_h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(_h)

misperrors = {"error": "Something went wrong"}
mispattributes = {
    "userConfig": {
        "AI_PROVIDER": {
            "type": "list",
            "values": ["openai", "anthropic", "gemini", "ollama"],
            "default": os.getenv("AI_PROVIDER", "openai"),
            "message": "Select LLM backend"
        },
        "OPENAI_MODEL": {"type": "string", "message": "OpenAI model name", "default": os.getenv("OPENAI_MODEL", "gpt-4o-mini")},
        "ANTHROPIC_MODEL": {"type": "string", "message": "Anthropic model name", "default": os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")},
        "GEMINI_MODEL": {"type": "string", "message": "Gemini model name", "default": os.getenv("GEMINI_MODEL", "gemini-1.5-pro")},
        "OLLAMA_HOST": {"type": "string", "message": "Ollama host URL", "default": os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")},
        "OLLAMA_MODEL": {"type": "string", "message": "Ollama model name", "default": os.getenv("OLLAMA_MODEL", "llama3.1")},
        "LIMIT_NUM_ATTRIBUTES": {"type": "string", "message": "Max attributes to send. Blank for all", "default": ""},
        "EXCLUDE_TYPES_CSV": {"type": "string", "message": "Exclude attribute types CSV. Blank for none", "default": ""},
        "MISP_URL": {"type": "string", "message": "MISP URL", "default": os.getenv("MISP_URL", "")},
        "MISP_VERIFY_SSL": {"type": "boolean", "message": "Verify SSL for MISP", "default": os.getenv("MISP_VERIFY_SSL", "true").lower() == "true"},
    },
    "format": "misp_standard",
    "input": ["misp_event", "misp_events"],
    "output": "misp_standard"
}

moduleinfo = {
    "version": MODULE_VERSION,
    "author": "haKC.ai",
    "description": "AI evidence-only analysis of MISP event data. Creates a new event with IoCs and a technical Event Report.",
    "module-type": ["expansion"],
    "name": "AI Event Analysis"
}

AI_TAG = "VALIDATION REQUIRED - AI Analysis"
EVENT_REPORT_TITLE = "AI Technical Analysis Report"

def _safe_int(v: str, default: Optional[int]) -> Optional[int]:
    try:
        v = v.strip()
        if not v:
            return default
        x = int(v)
        return x if x > 0 else default
    except Exception:
        return default

def _redact(s: str) -> str:
    if not s:
        return s
    return s[:4] + "****" if len(s) > 8 else "****"

def introspection() -> Dict[str, Any]:
    return mispattributes

def version() -> str:
    return MODULE_VERSION

def _read_provider(cfg: Dict[str, Any]) -> str:
    p = cfg.get("AI_PROVIDER") or os.getenv("AI_PROVIDER", "openai")
    return p.strip().lower()

def _provider_clients():
    clients = {}
    if OpenAIClient and os.getenv("OPENAI_API_KEY"):
        clients["openai"] = OpenAIClient(api_key=os.getenv("OPENAI_API_KEY"))
    if anthropic and os.getenv("ANTHROPIC_API_KEY"):
        clients["anthropic"] = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    if genai and os.getenv("GOOGLE_API_KEY"):
        genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
        clients["gemini"] = True
    if ollama:
        clients["ollama"] = True
    return clients

def _collect_event_material(ev: Dict[str, Any], exclude_types: set, limit: Optional[int]) -> Dict[str, Any]:
    core = {
        "Event": {
            "uuid": ev.get("uuid"),
            "info": ev.get("info"),
            "threat_level_id": ev.get("threat_level_id"),
            "analysis": ev.get("analysis"),
            "date": ev.get("date"),
            "tags": [t.get("name") for t in ev.get("Tag", []) if t.get("name")]
        },
        "Attributes": [],
        "Objects": []
    }
    attrs = ev.get("Attribute", []) or []
    if exclude_types:
        attrs = [a for a in attrs if a.get("type") not in exclude_types]
    if limit:
        attrs = attrs[:limit]
    core["Attributes"] = [
        {
            "uuid": a.get("uuid"),
            "type": a.get("type"),
            "category": a.get("category"),
            "value": a.get("value"),
            "comment": a.get("comment"),
            "tags": [t.get("name") for t in (a.get("Tag") or []) if t.get("name")]
        } for a in attrs
    ]
    objs = ev.get("Object", []) or []
    for o in objs:
        oattrs = o.get("Attribute", []) or []
        if exclude_types:
            oattrs = [a for a in oattrs if a.get("type") not in exclude_types]
        if limit:
            oattrs = oattrs[:limit]
        core["Objects"].append({
            "name": o.get("name"),
            "meta_category": o.get("meta-category"),
            "uuid": o.get("uuid"),
            "attributes": [
                {
                    "type": a.get("type"),
                    "category": a.get("category"),
                    "value": a.get("value"),
                    "comment": a.get("comment")
                } for a in oattrs
            ]
        })
    return core

def _build_ai_prompt(dataset: List[Dict[str, Any]]) -> str:
    rules = [
        "Analyze only the supplied event data. No external knowledge.",
        "No speculation. Every finding must map to explicit evidence in the data.",
        "Identify nuanced relationships across attributes, objects, and tags.",
        "Correlate infrastructure pivots, certificate reuse, clustering, TTP hints, and repeatable patterns.",
        "Produce JSON with fields: findings[], iocs[], objects[], narrative, analysis_log[].",
        "Each finding: title, confidence, evidence_refs[].",
        "Each ioc: type, value, category, comment.",
        "Each object: name, attributes[].",
        "Narrative is a technical report built strictly on the evidence.",
        "analysis_log is a concise step list of how the analysis was performed."
    ]
    payload = {"policy": rules, "dataset": dataset}
    return json.dumps(payload, separators=(",", ":"))


def _call_openai(prompt: str, model: str, timeout_s: int) -> str:
    client = OpenAIClient(api_key=os.getenv("OPENAI_API_KEY"))
    r = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are a senior cyber analyst. Follow the policy. Output pure JSON. No prose."},
            {"role": "user", "content": prompt}
        ],
        temperature=0,
        timeout=timeout_s,
        max_tokens=int(os.getenv("MAX_OUTPUT_TOKENS", "2000"))
    )
    return r.choices[0].message.content

def _call_anthropic(prompt: str, model: str, timeout_s: int) -> str:
    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    msg = client.messages.create(
        model=model,
        max_tokens=int(os.getenv("MAX_OUTPUT_TOKENS", "2000")),
        temperature=0,
        timeout=timeout_s,
        system="You are a senior cyber analyst. Follow the policy. Output pure JSON. No prose.",
        messages=[{"role": "user", "content": prompt}]
    )
    text = "".join([b.text for b in msg.content if hasattr(b, "text")])
    return text

def _call_gemini(prompt: str, model: str, timeout_s: int) -> str:
    genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
    mdl = genai.GenerativeModel(model)
    r = mdl.generate_content(
        [{"text": "You are a senior cyber analyst. Follow the policy. Output pure JSON. No prose."},
         {"text": prompt}],
        generation_config={"temperature": 0, "max_output_tokens": int(os.getenv("MAX_OUTPUT_TOKENS", "2000"))},
        safety_settings=[]
    )
    return r.text

def _call_ollama(prompt: str, model: str, timeout_s: int) -> str:
    res = ollama.chat(
        model=model,
        messages=[
            {"role": "system", "content": "You are a senior cyber analyst. Follow the policy. Output pure JSON. No prose."},
            {"role": "user", "content": prompt}
        ],
        options={"num_predict": int(os.getenv("MAX_OUTPUT_TOKENS", "2000")), "temperature": 0}
    )
    return res.get("message", {}).get("content", "")

def _run_llm(provider: str, prompt: str, cfg: Dict[str, Any], timeout_s: int) -> str:
    if provider == "openai":
        model = cfg.get("OPENAI_MODEL") or os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        return _call_openai(prompt, model, timeout_s)
    if provider == "anthropic":
        model = cfg.get("ANTHROPIC_MODEL") or os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")
        return _call_anthropic(prompt, model, timeout_s)
    if provider == "gemini":
        model = cfg.get("GEMINI_MODEL") or os.getenv("GEMINI_MODEL", "gemini-1.5-pro")
        return _call_gemini(prompt, model, timeout_s)
    if provider == "ollama":
        model = cfg.get("OLLAMA_MODEL") or os.getenv("OLLAMA_MODEL", "llama3.1")
        return _call_ollama(prompt, model, timeout_s)
    raise RuntimeError("Unknown provider")

def _clean_json_block(s: str) -> str:
    m = re.search(r"\{.*\}\s*$", s.strip(), re.S)
    return m.group(0) if m else s.strip()

def _mk_misp_client() -> Optional[ExpandedPyMISP]:
    if not ExpandedPyMISP:
        return None
    url = os.getenv("MISP_URL") or ""
    key = os.getenv("MISP_API_KEY") or ""
    verify = (os.getenv("MISP_VERIFY_SSL", "true").lower() == "true")
    if not url or not key:
        return None
    return ExpandedPyMISP(url, key, ssl=verify, debug=False)

def _attach_tag(obj, tag: str):
    if not tag:
        return
    try:
        obj.add_tag(tag)
    except Exception:
        pass

def _push_results_to_new_event(misp: ExpandedPyMISP, parsed: Dict[str, Any], source_event_uuids: List[str]) -> Dict[str, Any]:
    ev = MISPEvent()
    ev.info = "AI Analysis derived from: " + ", ".join(source_event_uuids)
    ev.analysis = 2
    ev.threat_level_id = 2
    _attach_tag(ev, AI_TAG)
    new = misp.add_event(ev)

    iocs = parsed.get("iocs", []) or []
    for i in iocs:
        attr = {
            "type": i.get("type"),
            "category": i.get("category") or "External analysis",
            "value": i.get("value"),
            "comment": (i.get("comment") or "") + f" [{AI_TAG}]"
        }
        try:
            misp.add_attribute(new, **attr)
        except Exception:
            pass

    objs = parsed.get("objects", []) or []
    for o in objs:
        mo = MISPObject(name=o.get("name") or "ai-finding")
        for a in o.get("attributes", []) or []:
            try:
                mo.add_attribute(a.get("type") or "text", value=a.get("value"), comment=(a.get("comment") or ""))
            except Exception:
                continue
        try:
            misp.add_object(new, mo)
        except Exception:
            pass

    findings = parsed.get("findings", []) or []
    if findings:
        table = [f"- {f.get('title','Untitled')} | confidence: {f.get('confidence','unknown')}" for f in findings]
        summary = "\n".join(table)
    else:
        summary = "No discrete findings list provided by AI."

    narrative = parsed.get("narrative") or "No narrative returned."
    analysis_log = parsed.get("analysis_log") or []

    appendix = ""
    if analysis_log:
        appendix = "\n## Technical Appendix\n" + "\n".join([f"- {step}" for step in analysis_log])

    report_md = f"# {EVENT_REPORT_TITLE}\n\n## Summary\n{summary}\n\n## Technical Narrative\n{narrative}\n{appendix}\n"
    try:
        misp.add_event_report(new["Event"]["uuid"], EVENT_REPORT_TITLE, report_md)
    except Exception:
        pass

    try:
        misp.tag(new["Event"]["uuid"], AI_TAG)
    except Exception:
        pass

    return {"created_event_uuid": new["Event"]["uuid"], "event_id": new["Event"]["id"]}

def handler(q: Dict[str, Any]) -> Dict[str, Any]:
    try:
        cfg = q.get("config", {}) or {}
        provider = _read_provider(cfg)
        timeout_s = int(os.getenv("LLM_TIMEOUT_SECONDS", "90"))
        limit = _safe_int(cfg.get("LIMIT_NUM_ATTRIBUTES",""), None)
        exclude_csv = (cfg.get("EXCLUDE_TYPES_CSV") or "").strip()
        exclude_types = set([t.strip() for t in exclude_csv.split(",") if t.strip()]) if exclude_csv else set()

        dataset = []
        src_event_uuids = []

        if "misp_events" in q and isinstance(q["misp_events"], list):
            for ev in q["misp_events"]:
                src_event_uuids.append(ev.get("uuid"))
                dataset.append(_collect_event_material(ev, exclude_types, limit))
        elif "misp_event" in q and isinstance(q["misp_event"], dict):
            ev = q["misp_event"]
            src_event_uuids.append(ev.get("uuid"))
            dataset.append(_collect_event_material(ev, exclude_types, limit))
        else:
            return {"error": "Expect misp_event or misp_events"}

        prompt = _build_ai_prompt(dataset)
        logger.info(f"Provider={provider}")

        raw = _run_llm(provider, prompt, cfg, timeout_s)
        cleaned = _clean_json_block(raw)
        parsed = json.loads(cleaned)

        misp = _mk_misp_client()
        if not misp:
            return {"results": {"analysis": parsed, "note": "MISP_URL or MISP_API_KEY not set. Returning AI JSON only."}}

        created = _push_results_to_new_event(misp, parsed, [u for u in src_event_uuids if u])
        return {"results": {"analysis": parsed, "created_event": created}}

    except Exception as e:
        logger.error(f"Error: {e}")
        return {"error": str(e)}

def requirements() -> List[str]:
    return ["pymisp", "python-dotenv", "requests", "httpx", "openai", "anthropic", "google-generativeai", "ollama"]
