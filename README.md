# MISP AIModule
![AI Expansion Module](images/AIM.png)


```
.
├── README.md
├── dev_misp_builder
│   ├── README.md
│   └── misp_dev_builder_installer_hardened.sh
├── modules
│   └── expansion
│       └── ai_event_analysis.py
├── requirements.txt
├── sample_exclude_types.csv
└── tools
    └── misp_server_prep.py
```

## What it does

- Sends one or more MISP events to a selected LLM provider and requests evidence only analysis
- Creates a new MISP event holding IoCs, structured MISP Objects, and an Event Report
- The Event Report includes a Technical Appendix of analysis steps so reviewers can see how conclusions were drawn
- Tags new content with `VALIDATION REQUIRED - AI Analysis`

## System flow: preprocessing, analysis, and write-back
```mermaid
flowchart TB
  %% Inputs
  IN1["Input: misp_event or misp_events"]
  IN2["Config: .env + userConfig"]
  IN3["Optional: exclude_types.csv or EXCLUDE_TYPES_CSV var"]

  %% Prep
  subgraph PREP["Server Prep Wizard"]
    P1["Install or verify Ollama"]
    P2["Pull selected models"]
    P3["Set AI provider and API keys"]
    P4["Set MISP_URL, MISP_API_KEY, MISP_VERIFY_SSL"]
    P5["Optionally create MISP Org: AI Analysis Only"]
    P6["Simulated checks LLM + MISP"]
    P7["Commit step with backup reminder"]
    P8["Logs: misp_prep.log"]
  end

  %% Expansion run
  subgraph RUN["Expansion Module ai_event_analysis.py"]
    direction TB
    R1["Load config and env"]
    R2["Resolve provider and model"]
    R3["Normalize input events"]
    R4["Apply EXCLUDE_TYPES_CSV filter"]
    R5["Apply LIMIT_NUM_ATTRIBUTES"]
    R6["Extract minimal evidence dataset: Event, Attributes, Objects"]
    R7["Build strict evidence only JSON prompt with policy"]
    DEC1{"Provider switch"}
    OAI["Call OpenAI"]
    ANT["Call Anthropic"]
    GEM["Call Gemini"]
    OLL["Call Ollama"]
    R8["Receive raw model output"]
    R9["Extract strict JSON block"]
    R10["Parse JSON to: findings[], iocs[], objects[], narrative, analysis_log[]"]
    DEC2{"MISP creds present"}
    R11["Create new MISP event"]
    R12["Add IoCs as Attributes. Append [VALIDATION REQUIRED - AI Analysis] to comments"]
    R13["Add MISP Objects returned by model"]
    R14["Build Event Report: Summary, Technical Narrative, Technical Appendix (analysis_log)"]
    R15["Tag event with VALIDATION REQUIRED - AI Analysis"]
    R16["Return created event id + uuid"]
    R17["If no creds: return AI JSON only"]
    LG["Operational logs"]
  end

  %% Wiring
  IN1 --> R1
  IN2 --> R1
  IN3 --> R4
  PREP --> R1

  R1 --> R2 --> R3 --> R4 --> R5 --> R6 --> R7 --> DEC1
  DEC1 -->|openai| OAI --> R8
  DEC1 -->|anthropic| ANT --> R8
  DEC1 -->|gemini| GEM --> R8
  DEC1 -->|ollama| OLL --> R8

  R8 --> R9 --> R10 --> DEC2
  DEC2 -->|yes| R11 --> R12 --> R13 --> R14 --> R15 --> R16
  DEC2 -->|no| R17

  R1 -.-> LG
  R2 -.-> LG
  R4 -.-> LG
  R8 -.-> LG
  R10 -.-> LG
  R14 -.-> LG

```

## Sequence: single run against one event

```mermaid
sequenceDiagram
  participant User
  participant MISP
  participant Expansion as ai_event_analysis.py
  participant LLM as Provider API
  participant NewEvent as New MISP Event

  User->>MISP: Run expansion on Event UUID E
  MISP->>Expansion: Provide misp_event + userConfig
  Note right of Expansion: Load .env, parse config, read EXCLUDE_TYPES_CSV, LIMIT_NUM_ATTRIBUTES

  Expansion->>Expansion: Filter attributes by type list and limit
  Expansion->>Expansion: Build dataset {Event, Attributes, Objects}
  Expansion->>Expansion: Build strict evidence only JSON prompt

  alt Provider selection
    Expansion->>LLM: Chat with system policy + prompt
    LLM-->>Expansion: JSON {findings, iocs, objects, narrative, analysis_log}
  end

  Expansion->>Expansion: Parse JSON, validate schema

  alt MISP creds available
    Expansion->>MISP: Create new event
    MISP-->>Expansion: New event uuid U
    Expansion->>NewEvent: Add Attributes for IoCs with comment suffix [VALIDATION REQUIRED - AI Analysis]
    Expansion->>NewEvent: Add MISP Objects from response
    Expansion->>NewEvent: Add Event Report with Summary, Technical Narrative, Technical Appendix
    Expansion->>NewEvent: Tag event with VALIDATION REQUIRED - AI Analysis
    Expansion-->>MISP: Return {event_id, uuid}
  else No creds
    Expansion-->>MISP: Return AI JSON only
  end
```

## Why a dedicated AI Org matters

You can create and use a dedicated MISP Organisation for AI outputs, for example `AI Analysis Only`. Only share events with this org that you want analyzed. This isolates AI generated content and gives you an explicit control gate.

## Install

While this *SHOULD* be production friendly, I highly recommend testing first on a development environment.


```bash
git clone https://github.com/haKC-ai/misp_ai_expansion_module.git
cd misp-ai-expansion
./installer.sh --prep
````

* `--prep` launches the server prep wizard described below.

## MISP Server Prep wizard

Run anytime:

```bash
. ./.venv/bin/activate
python tools/misp_server_prep.py
```

Capabilities:

* Install or verify Ollama, and pull selected models
* Set AI provider and API keys into `.env`
* Set `MISP_URL`, `MISP_API_KEY`, `MISP_VERIFY_SSL`
* Optionally create a new Organisation in MISP, default name `AI Analysis Only`
* Simulated checks: validates LLM connectivity and MISP connectivity without mutating data
* Commit step with a reminder to back up first
* All actions are logged to `misp_prep.log`

## Config

`.env` keys:

```
AI_PROVIDER=openai|anthropic|gemini|ollama
OPENAI_API_KEY=...
ANTHROPIC_API_KEY=...
GOOGLE_API_KEY=...
OLLAMA_HOST=http://127.0.0.1:11434
...
MISP_URL=https://your.misp.local
MISP_API_KEY=...
MISP_VERIFY_SSL=true
```

Limiters:

* `LIMIT_NUM_ATTRIBUTES` optional integer
* `EXCLUDE_TYPES_CSV` optional CSV of attribute types to omit

Example:

- Say you don’t want attachments or malware samples analyzed:
```
attachment,malware-sample
```

- Skip large blobs and crypto artifacts:
```
attachment,malware-sample,x509-fingerprint-md5,x509-fingerprint-sha1,x509-fingerprint-sha256
```

`Key details`

- The strings must match official MISP attribute type names exactly (case-sensitive).

 -- There are no headers, no quotes, just a flat CSV string.
 -- You put this in the module config (or in .env as EXCLUDE_TYPES_CSV=...).

 -- Reference for valid names

 -- The full list of valid attribute types is maintained in the MISP core docs:
https://www.misp-project.org/datamodels/#attributes

## Running the expansion module

Invoke via MISP expansion on an event or API call with `misp_event` or `misp_events`. The module returns the new event id and uuid when MISP credentials are present.

## Output contents

* New event with tag `VALIDATION REQUIRED - AI Analysis`
* IoCs as attributes, each attribute comment includes `[VALIDATION REQUIRED - AI Analysis]`
* Structured MISP Objects when returned by the model
* Event Report titled `AI Technical Analysis Report` with sections:

  * Summary
  * Technical Narrative
  * Technical Appendix listing analysis steps

## Disclaimer

Use of AI must be operator controlled and audited. Keep AI access scoped by placing events into the dedicated AI Organisation only when you intend to analyze them. Always validate outputs. Back up your MISP before committing configuration changes.

## Security practices

* Evidence only prompt
* Temperature 0
* Strict timeouts
* No external lookups
* Keys never logged in plaintext

