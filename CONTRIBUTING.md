# Contributing to Qcrypt

Welcome to `qcrypt`. This project is an advanced cryptographic engine specializing in ML-KEM encapsulation, AES-GCM streaming, and steganography. 

## Development Paradigm (AI-Driven)

This repository is primarily maintained and extended by an autonomous AI Agent (Antigravity). Human contributors are welcome, but the primary method for submitting feature requests, bug reports, and architectural changes is to engage the AI Agent.

If you encounter an issue or desire a new feature:
1. Open an Issue outlining the problem or request.
2. The AI Agent will read the issue, orchestrate the necessary codebase changes, run integration tests, and submit a Pull Request.

## Documentation Standard (OKF)

This project strictly adheres to the **Open Knowledge Format (OKF)** standard.
- All domain logic, APIs, and subsystems MUST be documented in the `docs/knowledge/` directory.
- OKF files use strict YAML frontmatter mapping to a deterministic Directed Acyclic Graph (DAG) starting at `docs/knowledge/index.md`.
- Any Pull Request (whether human or AI-generated) that introduces new logic but fails to update the corresponding OKF document will be rejected.

### Universal AI Documentation Prompt
If you are using an external LLM to write or update documentation for this project, copy and paste the following prompt to ensure the output complies with our strict DAG structure:

```text
You are generating documentation for the `qcrypt` project. You MUST output your response strictly adhering to the Open Knowledge Format (OKF).

OKF Structural Rules:
1. The document MUST begin with YAML frontmatter bounded by `---`.
2. The frontmatter MUST include:
   - `id`: Globally unique lowercase kebab-case ID matching `^[a-z0-9]+(\.[a-z0-9-]+)+$` (e.g., `domain.subdomain.concept`).
   - `title`: Human-readable title.
   - `version`: Semantic version (e.g., `1.0.0`).
   - `tags`: Hierarchical list (e.g., `category/subcategory`). Max 10 tags.
   - `description`: Single sentence summary.
   - `references`: List of related concept IDs.
3. Following the YAML block, leave exactly one blank line before starting the Markdown body.
4. Use `[[domain.subdomain.concept]]` format when linking to other OKF documents in the body.
5. If wrapping an external schema, duplicate essential metadata into a `schema_metadata` YAML block.

Do not include narrative filler. Output the raw OKF document only.
```

## Code Style
- `rustfmt` is mandatory.
- Code should be written for maximum performance and zero-allocation where possible, particularly in `core.engine.pipeline`.
- Cryptographic keys MUST be locked in volatile memory using `memsec` and zeroized on drop.

## Testing
All PRs must pass the integration tests. Run tests locally using:
```bash
cargo test
```
