## Sequence Diagram — Vens CLI (data flow)

This diagram describes the end‑to‑end flow as specified (report reading, data conversion, batch processing with exponential backoff, community and contextual scoring via LLM, global score, prioritization, output).

```mermaid
sequenceDiagram
    autonumber
    actor User as User
    participant CLI as Vens CLI
    participant FS as Report file (input)
    participant Parser as Parser/Deserializer
    participant Cfg as Context Sources (Configs/Vendors)
    participant Assets as Assets Builder
    participant Conv as Converter (ext→int)
    participant Batch as Batch Processor
    participant Comm as Community Scoring Engine
    participant LLM as LLM
    participant Sim as Similarity Engine (AI)
    participant Ctx as Contextual Scoring Engine
    participant Pri as Prioritization Engine
    participant Out as Output

    User->>CLI: 1. Run command (with report path)
    CLI->>FS: 1.a. Read report file
    FS-->>CLI: Raw content
    CLI->>Parser: 1.b. Deserialize into Report struct
    Parser-->>CLI: Report struct
    CLI->>Parser: 1.c. Extract Vulnerabilities list
    Parser-->>CLI: []source.Vulnerability
    CLI->>Cfg: 1.d. Load context (component scores, libraries)
    Cfg-->>Assets: Raw context data
    Assets-->>CLI: generator.Assets (assets + associated libraries)

    CLI->>Conv: 2.a. Convert each source.Vulnerability → generator.Vulnerability
    Conv-->>CLI: []generator.Vulnerability

    CLI->>Batch: 3.a. Process in batches (size=10, exponential backoff retries)
    loop For each batch (10 vulns by default)
        Batch->>Batch: Scheduling + retry strategy (exponential backoff)
        loop For each Vulnerability in the batch
            Batch->>Comm: 4. Compute Community Scoring
            Comm-->>Batch: community_score

            Batch->>Ctx: 5. Compute contextual score (LLM)
            Note right of Ctx: 5.a. Extract library names via LLM
            Ctx->>LLM: Prompt to extract libs from the vulnerability
            LLM-->>Ctx: Candidate libs list

            Note right of Sim: 5.b. Match libs (vuln vs assets)
            Ctx->>Sim: Semantic similarity (AI search)
            Sim-->>Ctx: Likely library↔component pairs

            Note right of Ctx: 5.c–d. Filter impacted libs + JSON schema
            Ctx->>LLM: Filter and return JSON conforming to the schema
            LLM-->>Ctx: JSON of impacted libs
            Ctx->>Ctx: 5.e. Deserialize LLM output
            Ctx-->>Batch: impacted_libs + context

            Batch->>Ctx: 5.c (cont.) Compute contextual score
            Ctx-->>Batch: contextual_score

            Batch->>Batch: 6. Global score = f(community_score, contextual_score)
            Batch-->>Pri: 7. Apply prioritization logic
            Pri-->>Batch: Adjusted priority/severity
        end
    end

    Batch-->>Out: 8. Results (scores, priorities, impacted libs)
    Out-->>User: Display/Export (console, JSON, etc.)
```

Implementation notes:
- Batch processing: group of 10 vulnerabilities with exponential retries on LLM/IO failures.
- Community scoring: aggregate EPSS/KEV/CVSS/community signals per your strategy.
- Assets context: built from config files or vendors (SBOM, lockfiles, etc.) into generator.Assets.
- LLM: structured JSON outputs with a predefined schema for reliable deserialization.
- Global score: weighted or logical combination (AND/Min) between community and contextual scores.
- Prioritization: apply business rules (SLAs, component/service criticality, exceptions/VEX, etc.).


## High‑Level Design (Graph) — Vens CLI (exactly aligned with the sequence diagram)

This graph shows the high‑level flow only, aligned with the simplified sequence diagram. It keeps the main steps 1–8 and removes sub‑steps like 1.a or 6.a–6.e for clarity.

```mermaid
flowchart LR
    %% Participants (high-level only)
    User([User])
    CLI([Vens CLI])
    FS[(Report file input)]
    Parser[[Parser/Deserializer]]
    Cfg[[Context Sources: Configs/Vendors]]
    Assets[[Assets Builder]]
    Conv[[Converter: ext→int]]
    Batch[[Batch Processor]]
    Comm[[Community Scoring Engine]]
    Ctx[[Contextual Scoring Engine]]
    Pri[[Prioritization Engine]]
    Out[[Output]]

    %% High-level steps 1–8
    User -- "1. Run command with report path" --> CLI
    CLI -- "2. Parse report and extract vulnerabilities" --> Parser
    Parser -- "Vulnerabilities" --> CLI

    CLI -- "3. Load context sources" --> Cfg
    Cfg -->|"Build assets context"| Assets
    Assets -->|"Assets"| CLI

    CLI -- "4. Convert vulnerabilities to internal model" --> Conv
    Conv -- "Converted vulnerabilities" --> CLI

    CLI -- "5. Process in batches with retries" --> Batch

    Batch -->|"Compute community scoring"| Comm
    Comm -->|"community_score"| Batch

    Batch -->|"Compute contextual scoring"| Ctx
    Ctx -->|"contextual_score + impacted_libs"| Batch

    Batch -->|"7. Global scoring and prioritization"| Pri
    Pri -->|"prioritized results"| Batch

    Batch -->|"8. Results (scores, priorities, impacted libs)"| Out
    Out -->|"Display/Export"| User
```


## System Design (Excalidraw SVG)

The following embedded SVG provides a visual system design overview drawn in Excalidraw.

![Vens System Design — Excalidraw](system-design-2025-11-03.excalidraw.svg)
