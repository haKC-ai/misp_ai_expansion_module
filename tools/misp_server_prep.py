#!/usr/bin/env python3
import os, sys, json, subprocess, logging, shutil, time, platform
from typing import List, Dict
from dotenv import load_dotenv
from simple_term_menu import TerminalMenu

LOG_PATH = os.environ.get("PREP_LOG_PATH", os.path.abspath("./misp_prep.log"))
logging.basicConfig(filename=LOG_PATH, level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
console = logging.StreamHandler(sys.stdout)
console.setLevel(logging.INFO)
console.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logging.getLogger().addHandler(console)

load_dotenv()

ENV_PATH = os.path.abspath(".env")
DEFAULT_ORG_NAME = os.environ.get("AI_ORG_NAME", "AI Analysis Only")
OLLAMA_HOST_DEFAULT = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
OLLAMA_MODELS_DEFAULT = ["llama3.1", "qwen2.5", "mistral-nemo"]

def choose(title: str, items: List[str], multi: bool = False) -> List[str]:
    m = TerminalMenu(items, title=title, multi_select=multi, show_multi_select_hint=multi)
    idx = m.show()
    if idx is None:
        return []
    return list(m.chosen_menu_entries) if multi else [items[idx]]

def write_env(updates: Dict[str, str]):
    lines = []
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    kv = {}
    for ln in lines:
        if "=" in ln and not ln.strip().startswith("#"):
            k, v = ln.split("=", 1)
            kv[k.strip()] = v
    kv.update(updates)
    with open(ENV_PATH, "w", encoding="utf-8") as f:
        for k in sorted(kv.keys()):
            v = kv[k]
            f.write(f"{k}={v}\n")
    logging.info("Updated .env with keys: %s", ", ".join(sorted(updates.keys())))

def is_ollama_running() -> bool:
    try:
        import ollama
        r = ollama.list()
        logging.info("Ollama reachable. Models count: %d", len(r.get("models", [])))
        return True
    except Exception as e:
        logging.info("Ollama not reachable: %s", e)
        return False

def install_ollama():
    os_name = platform.system().lower()
    logging.info("Attempting Ollama install for %s", os_name)
    try:
        if shutil.which("ollama"):
            logging.info("Ollama binary present: %s", shutil.which("ollama"))
            return True
        if os_name == "linux":
            subprocess.run(["bash", "-lc", "curl -fsSL https://ollama.com/install.sh | sh"], check=True)
        elif os_name == "darwin":
            if shutil.which("brew"):
                subprocess.run(["brew", "install", "ollama"], check=True)
            else:
                logging.error("Homebrew not found. Install brew or install Ollama manually.")
                return False
        else:
            logging.error("Unsupported OS for automated install. Install Ollama manually.")
            return False
        return True
    except Exception as e:
        logging.error("Failed to install Ollama: %s", e)
        return False

def pull_models(models: List[str]):
    ok = True
    try:
        import ollama
    except Exception as e:
        logging.error("Ollama lib import failed: %s", e)
        return False
    for m in models:
        try:
            logging.info("Pulling model: %s", m)
            ollama.pull(m)
        except Exception as e:
            logging.error("Failed to pull %s: %s", m, e)
            ok = False
    return ok

def set_provider_env():
    items = ["Provider: OpenAI", "Provider: Anthropic", "Provider: Gemini", "Provider: Ollama"]
    sel = choose("Select AI provider", items, multi=False)
    if not sel:
        return
    p = sel[0].split(":")[1].strip().lower()
    updates = {"AI_PROVIDER": p}
    if p == "openai":
        updates["OPENAI_API_KEY"] = os.environ.get("OPENAI_API_KEY", input("OPENAI_API_KEY: ").strip())
        updates["OPENAI_MODEL"] = os.environ.get("OPENAI_MODEL", input("OPENAI_MODEL [gpt-4o-mini]: ").strip() or "gpt-4o-mini")
    elif p == "anthropic":
        updates["ANTHROPIC_API_KEY"] = os.environ.get("ANTHROPIC_API_KEY", input("ANTHROPIC_API_KEY: ").strip())
        updates["ANTHROPIC_MODEL"] = os.environ.get("ANTHROPIC_MODEL", input("ANTHROPIC_MODEL [claude-3-5-sonnet-latest]: ").strip() or "claude-3-5-sonnet-latest")
    elif p == "gemini":
        updates["GOOGLE_API_KEY"] = os.environ.get("GOOGLE_API_KEY", input("GOOGLE_API_KEY: ").strip())
        updates["GEMINI_MODEL"] = os.environ.get("GEMINI_MODEL", input("GEMINI_MODEL [gemini-1.5-pro]: ").strip() or "gemini-1.5-pro")
    elif p == "ollama":
        updates["OLLAMA_HOST"] = os.environ.get("OLLAMA_HOST", input(f"OLLAMA_HOST [{OLLAMA_HOST_DEFAULT}]: ").strip() or OLLAMA_HOST_DEFAULT)
        updates["OLLAMA_MODEL"] = os.environ.get("OLLAMA_MODEL", input("OLLAMA_MODEL [llama3.1]: ").strip() or "llama3.1")
    write_env(updates)

def set_misp_env():
    updates = {}
    updates["MISP_URL"] = os.environ.get("MISP_URL", input("MISP_URL: ").strip())
    updates["MISP_API_KEY"] = os.environ.get("MISP_API_KEY", input("MISP_API_KEY: ").strip())
    updates["MISP_VERIFY_SSL"] = os.environ.get("MISP_VERIFY_SSL", input("MISP_VERIFY_SSL [true|false] default true: ").strip() or "true")
    write_env(updates)

def create_ai_org_if_selected():
    from pymisp import ExpandedPyMISP
    org_name = input(f"Org name [{DEFAULT_ORG_NAME}]: ").strip() or DEFAULT_ORG_NAME
    url = os.environ.get("MISP_URL", "")
    key = os.environ.get("MISP_API_KEY", "")
    verify = (os.environ.get("MISP_VERIFY_SSL", "true").lower() == "true")
    if not url or not key:
        logging.error("MISP_URL or MISP_API_KEY missing. Skip org creation.")
        return
    try:
        m = ExpandedPyMISP(url, key, ssl=verify, debug=False)
        res = m.add_organisation(name=org_name)
        logging.info("Created org: %s", res.get("Organisation", {}).get("name", org_name))
    except Exception as e:
        logging.error("Org creation failed: %s", e)

def simulate_checks():
    steps = []
    ok = True
    steps.append("Beginning simulated checks")
    try:
        prov = os.environ.get("AI_PROVIDER", "")
        steps.append(f"Provider={prov}")
        if prov == "openai":
            from openai import OpenAI
            c = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", ""))
            c.models.list()
        elif prov == "anthropic":
            import anthropic
            anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", "")).models.list()
        elif prov == "gemini":
            import google.generativeai as genai
            genai.configure(api_key=os.environ.get("GOOGLE_API_KEY", ""))
            genai.list_models()
        elif prov == "ollama":
            import ollama
            ollama.list()
        steps.append("LLM connectivity OK")
        logging.info("LLM connectivity OK")
    except Exception as e:
        ok = False
        steps.append(f"LLM connectivity failed: {e}")
        logging.error("LLM connectivity failed: %s", e)

    try:
        from pymisp import ExpandedPyMISP
        url = os.environ.get("MISP_URL", "")
        key = os.environ.get("MISP_API_KEY", "")
        if url and key:
            ExpandedPyMISP(url, key, ssl=(os.environ.get("MISP_VERIFY_SSL", "true").lower()=="true"), debug=False).get_version()
            steps.append("MISP connectivity OK")
            logging.info("MISP connectivity OK")
        else:
            steps.append("MISP connectivity skipped")
            logging.info("MISP connectivity skipped")
    except Exception as e:
        ok = False
        steps.append(f"MISP connectivity failed: {e}")
        logging.error("MISP connectivity failed: %s", e)

    return ok, steps

def commit_to_misp_prompt():
    print("")
    print("Reminder: back up your MISP database and config before committing changes.")
    items = ["Proceed with commit", "Cancel"]
    sel = choose("Commit changes now", items, multi=False)
    if not sel or sel[0].startswith("Cancel"):
        logging.info("Commit canceled by user")
        return False
    logging.info("Proceeding with commit as requested")
    return True

def wizard():
    while True:
        items = [
            "Install or verify Ollama",
            "Pull Ollama models",
            "Set AI provider and keys",
            "Set MISP URL and API key",
            "Create AI Org in MISP",
            "Run simulated checks",
            "Commit to MISP",
            "Exit"
        ]
        sel = choose("MISP Server Prep", items, multi=False)
        if not sel:
            break
        choice = sel[0]
        if choice.startswith("Install"):
            if is_ollama_running() or install_ollama():
                logging.info("Ollama ready")
            else:
                logging.error("Ollama setup failed")
        elif choice.startswith("Pull"):
            models = choose("Select Ollama models to pull", OLLAMA_MODELS_DEFAULT, multi=True)
            if not models:
                logging.info("No models selected")
            else:
                ok = pull_models(models)
                logging.info("Model pulls result: %s", ok)
        elif choice.startswith("Set AI provider"):
            set_provider_env()
        elif choice.startswith("Set MISP"):
            set_misp_env()
        elif choice.startswith("Create AI Org"):
            create_ai_org_if_selected()
        elif choice.startswith("Run simulated"):
            ok, steps = simulate_checks()
            logging.info("Simulated checks OK=%s", ok)
            for s in steps:
                logging.info("CHECK: %s", s)
            print("Simulated checks OK" if ok else "Simulated checks failed. See log.")
        elif choice.startswith("Commit"):
            if commit_to_misp_prompt():
                logging.info("User confirmed commit step")
                print("Committed prep changes. Review your MISP settings if needed.")
        elif choice.startswith("Exit"):
            break

if __name__ == "__main__":
    try:
        wizard()
    except KeyboardInterrupt:
        logging.info("Prep wizard interrupted by user")
