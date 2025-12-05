## Sequence Diagram — Vens CLI (data flow)

This diagram describes the end‑to‑end flow as specified (report reading, data conversion, batch processing with exponential backoff, community and contextual scoring via LLM, global score, prioritization, output).

```mermaid
sequenceDiagram
    autonumber
    actor User as User
    participant CLI as Vens CLI
    participant Risk as Risk Config (config.yaml)
    participant SBOM as SBOMs CSV (list of SBOM paths)
    participant Assets as Assets Builder (from SBOMs)
    participant Vec as Vector Index (HNSW)
    participant FS as Vulnerabilities Report (input)
    participant Parser as Parser/Deserializer
    participant Conv as Converter (ext→int)
    participant Batch as Batch Processor
    participant Comm as Community Scoring Engine
    participant LLM as LLM
    participant Sim as Similarity Engine (AI)
    participant Ctx as Contextual Scoring Engine
    participant Out as CycloneDX VEX Output

    User->>CLI: 1. Run command (with inputs: report, config.yaml, sboms.csv)
    CLI->>Risk: 1.a. Read Risk config (config.yaml)
    Risk-->>CLI: Risk settings
    CLI->>SBOM: 1.b. Read CSV list of SBOMs
    SBOM-->>Assets: SBOM file paths
    Assets->>Assets: 1.c. Collect components and related libraries
    Assets->>Vec: 1.d. Index components/libs into HNSW (in-memory)
    Vec-->>Assets: Index ready
    CLI->>FS: 1.e. Read vulnerabilities report file
    FS-->>CLI: Raw report content
    CLI->>Parser: 1.f. Deserialize into Report struct
    Parser-->>CLI: Report struct
    CLI->>Parser: 1.g. Extract vulnerabilities → []source.Vulnerability
    Parser-->>CLI: []source.Vulnerability

    CLI->>Conv: 2.a. Convert each source.Vulnerability → generator.Vulnerability
    Conv-->>CLI: []generator.Vulnerability

    CLI->>Batch: 3.a. Process in batches (size=10, exponential backoff retries)
    loop For each batch (10 vulns by default)
        Batch->>Batch: Scheduling + retry strategy (exponential backoff)
        loop For each Vulnerability in the batch
            Batch->>Comm: 4. Compute Community Scoring (improvement)
            Comm-->>Batch: community_score

            Batch->>Ctx: 5. Compute contextual score (LLM)
            Note right of Ctx: 5.a. Extract library name from vulnerability
            Ctx->>LLM: Prompt to extract the library name from the vulnerability
            LLM-->>Ctx: Candidate library name

            Note right of Sim: 5.b. Match vuln library with components' libraries
            Ctx->>Sim: Similarity search over HNSW index
            Sim-->>Ctx: Likely library↔component pairs

            Note right of Ctx: 5.c–d. LLM filters and returns impacted libs (JSON schema)
            Ctx->>LLM: Filter and return JSON conforming to the schema
            LLM-->>Ctx: JSON of sboms impacted libs
            Ctx->>Ctx: 5.e. Deserialize LLM output
            Ctx-->>Batch: impacted_libs + context

            Batch->>Ctx: 5.c (cont.) Compute contextual score
            Ctx-->>Batch: contextual_score

            %% Final score combination step removed per updated data flow
        end
    end

    Batch-->>Out: 8. Generate CycloneDX VEX (scores, priorities, impacted libs)
    Out-->>User: Display/Export (console, JSON, etc.)
```

Implementation notes:
- Batch processing: group of 10 vulnerabilities with exponential retries on LLM/IO failures.
- Community scoring: aggregate EPSS/KEV/CVSS/community signals per your strategy.
- Assets context: built from Sboms.

- LLM: structured JSON outputs with a predefined schema for reliable deserialization.
- Output: generate CycloneDX VEX with impacted libraries and computed scores.


## High‑Level Design (Graph) — Vens CLI (exactly aligned with the sequence diagram)

This graph shows the high‑level flow only, aligned with the simplified sequence diagram. It keeps the main steps 1–8 and removes sub‑steps like 1.a or 6.a–6.e for clarity.

```mermaid
flowchart LR
    %% Participants (high-level only)
    User["User"];
    CLI["Vens CLI"];
    Risk["config.yaml - Risk config"];
    SBOMS["csv list of SBOMs"];
    Assets["Assets Builder (from SBOMs)"];
    Vec["Vector Index (HNSW)"];
    FS["Vulnerabilities report"];
    Parser["Parser/Deserializer"];
    Conv["Converter ext to int"];
    Batch["Batch Processor"];
    Comm["Community Scoring Engine"];
    Ctx["Contextual Scoring Engine"];
    Out["CycloneDX VEX Output"];

    %% High-level steps 1–8
    User -->|1. Run command with report, config.yaml, sboms.csv| CLI;
    CLI -->|2. Read Risk config| Risk;
    CLI -->|3. Read SBOMs list| SBOMS;
    SBOMS -->|Build assets context| Assets;
    Assets -->|Index components/libs| Vec;
    Vec -->|Index ready| Assets;
    CLI -->|4. Parse report and extract vulnerabilities| Parser;
    Parser -->|Vulnerabilities| CLI;

    Assets -->|Assets| CLI;

    CLI -->|5. Convert vulnerabilities to internal model| Conv;
    Conv -->|Converted vulnerabilities| CLI;

    CLI -->|6. Process in batches with retries| Batch;

    Batch -->|Compute community scoring| Comm;
    Comm -->|community_score| Batch;

    Batch -->|Compute contextual scoring| Ctx;
    Ctx -->|contextual_score + impacted_libs| Batch;

    %% Final score combination step removed per updated data flow

    Batch -->|8. Generate CycloneDX VEX (scores, priorities, impacted libs)| Out;
    Out -->|Display/Export| User;
```


## System Design (Excalidraw SVG)

The following embedded SVG provides a visual system design overview drawn in Excalidraw.

![Vens System Design — Excalidraw](system-design-2025-11-03.excalidraw.svg)


## Score Factory — Steps

`Score Factory` scoring workflow.

```mermaid
flowchart LR
    %% Left side: Similarity matching between vulnerability lib and SBOM libs/components
    subgraph MatchingPhase[AI similarity search to match vulnerability library with SBOM libraries and components]
        VL[Vulnerability Library]
        S1[(SBOM Library)]
        S2[(SBOM Library)]
        S3[(SBOM Library)]
        C1[(Component1 Purl)]
        C2[(Component2 Purl)]
        C3[(Component3 Purl)]

        VL -->|similarity search| S1
        VL -->|similarity search| S2
        VL -->|similarity search| S3

        S1 --> C1
        S2 --> C2
        S3 --> C3
    end

    %% Pass candidates to LLM to filter SBOM libraries
    VL -.->|"Pass to LLM to filter sboms libraries"| LLM[[LLM Filter]]
    S1 -.-> LLM
    S2 -.-> LLM
    S3 -.-> LLM

    %% LLM returns the impacted library and its mapped component
    LLM --> IL[(Filtered/impacted sboms libraries)]
    IL --> ICP[(Impacted Component Purl)]

    %% Generate VEX from impacted items
    IL -->|generate VEX| VEX[[VEX with component score]]
```
