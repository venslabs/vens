## Sequence Diagram — Vens CLI (data flow)

This diagram describes the end‑to‑end flow as specified (report reading, SBOM indexing, similarity matching, LLM filtering, and VEX generation with risk scores).

```mermaid
sequenceDiagram
    autonumber
    actor User as User
    participant CLI as Vens CLI
    participant Risk as Risk Config (config.yaml)
    participant SBOM as SBOMs (CycloneDX)
    participant Vec as Vector Index (In-memory)
    participant FS as Vulnerabilities Report (input)
    participant Parser as Parser/Deserializer
    participant Gen as Generator
    participant LLM as LLM (OpenAI/Ollama/etc.)
    participant Out as CycloneDX VEX Output

    User->>CLI: 1. Run command (report, config.yaml, sboms)
    CLI->>Risk: 1.a. Read Risk config (config.yaml)
    Risk-->>CLI: Risk settings
    
    CLI->>SBOM: 1.b. Index SBOM Libraries
    loop For each SBOM path
        SBOM->>CLI: Stream components
        CLI->>LLM: Generate embeddings
        LLM-->>CLI: Vectors
        CLI->>Vec: Add to index
    end
    Vec-->>CLI: Index ready (SBOMIndexBundle)

    CLI->>FS: 1.c. Read vulnerabilities report file
    FS-->>CLI: Raw report content
    CLI->>Parser: 1.d. Deserialize into Report struct
    Parser-->>CLI: Vulnerabilities

    CLI->>Gen: 2. Generate Risk Scores
    loop In batches (default 10)
        Gen->>LLM: 2.a. Embed vulnerability data
        LLM-->>Gen: Vectors
        Gen->>Vec: 2.b. Similarity search (top-K candidates)
        Vec-->>Gen: Candidate PURLs
        
        Gen->>LLM: 2.c. Filter impacted libraries (LLM)
        Note right of LLM: LLM matches vuln to specific candidates
        LLM-->>Gen: Selected PURLs
        
        Gen->>Risk: 2.d. Look up risk scores for selected PURLs
        Risk-->>Gen: Scores (OWASP)
    end

    Gen-->>Out: 3. Generate CycloneDX VEX (ratings, impacted libs)
    Out-->>User: Display/Export
```

Implementation notes:
- **SBOM Indexing**: Components from CycloneDX SBOMs are embedded and stored in an in-memory vector index for efficient similarity matching.
- **Batch Processing**: Vulnerabilities are processed in batches (default 10) to optimize LLM and embedding API calls.
- **Similarity Matching**: Uses vector embeddings to find candidate libraries in the SBOM that might be affected by a vulnerability.
- **LLM Filtering**: An LLM acts as an expert to refine the similarity search results, ensuring only truly relevant libraries are selected.
- **Risk Scoring**: Final scores are derived from user-provided OWASP risk ratings in `config.yaml`, mapped via PURLs.


## High‑Level Design (Graph) — Vens CLI

This graph shows the high‑level architectural components of Vens.

```mermaid
flowchart LR
    User["User"]
    CLI["Vens CLI"]
    Config["config.yaml (Risk)"]
    SBOM["SBOMs (CycloneDX)"]
    Report["Vulnerability Report"]
    Vec["Vector Index"]
    LLM["LLM Service (Embeddings/Chat)"]
    Gen["Generator"]
    Output["CycloneDX VEX"]

    User -->|Run| CLI
    CLI -->|Load| Config
    CLI -->|Index| SBOM
    SBOM -->|Embed| LLM
    LLM -->|Vectors| Vec
    CLI -->|Parse| Report
    Report -->|Vulns| Gen
    Gen -->|Match| Vec
    Gen -->|Refine| LLM
    Gen -->|Lookup| Config
    Gen -->|Generate| Output
    Output -->|Result| User
```


## Core Components

### 1. CLI Layer (`cmd/vens`)
Orchestrates the process, handles flags, and manages file I/O for reports, SBOMs, and configuration.

### 2. Generator (`pkg/generator`)
The central coordinator that:
- Manages SBOM indexing via `IndexSBOMLibraries`.
- Executes the risk scoring workflow in `GenerateRiskScore`.
- Orchestrates batching, embedding, similarity searching, and LLM filtering.

### 3. Vector Index (`pkg/vecindex`)
Provides an in-memory storage and search mechanism for component embeddings, enabling fast identification of candidate libraries.

### 4. Risk Configuration (`pkg/riskconfig`)
Parses and provides access to user-defined OWASP risk scores, mapping PURLs to specific likelihood and impact values.

### 5. LLM Abstraction (`pkg/llm`)
A factory-based layer that supports multiple LLM backends for both text generation (filtering) and vector embeddings.

### 6. SBOM Streamer (`pkg/sbom`)
Efficiently parses large CycloneDX SBOM files using streaming to minimize memory footprint during indexing.


## Risk Scoring Workflow

```mermaid
flowchart TD
    Vuln[Vulnerability] --> Embed[Generate Embedding]
    Embed --> Search[Vector Search in SBOM Index]
    Search --> Candidates[Top-K Candidate PURLs]
    Candidates --> LLM[LLM Refinement/Filtering]
    LLM --> Selected[Selected Impacted PURLs]
    Selected --> Lookup[Risk Config Lookup]
    Lookup --> Final[VEX with OWASP Scores]
```
