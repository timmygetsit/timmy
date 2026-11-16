# Contributing to TIMMY

Thank you for your interest in contributing to **TIMMY**! We welcome bug reports, performance enhancements, documentation improvements, and new AI agent attribution signatures.

---

## 1. Development Setup

### Requirements
- **Rust Toolchain**: 1.75 or later (stable channel recommended)
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  rustup update stable
  rustup component add rustfmt clippy
  ```
- **macOS**: macOS 12+ (Monterey, Ventura, Sonoma, Sequoia) on Apple Silicon or Intel.
- **SQLite3 development libraries**: Standard on macOS.

### Building & Running

```bash
# Clone the repository
git clone https://github.com/timmygetsit/timmy.git
cd timmy

# Verify compilation
cargo check

# Run test suite
cargo test

# Run interactive TUI in debug mode
cargo run
```

---

## 2. Code Quality & Standards

Before opening a pull request, ensure all validation checks pass cleanly:

```bash
# Check formatting
cargo fmt --check

# Run linter with pedantic checks
cargo clippy -- -D warnings

# Execute test suite
cargo test
```

### Architectural & Coding Rules:
1. **Separation of Concerns**: Never import UI types (`ratatui::*`, `crossterm::*`) inside the domain engine (`src/engine/`), platform layer (`src/platform/`), or storage modules (`src/storage/`).
2. **Error Handling**: Use `thiserror` for typed domain errors and `anyhow` for top-level application orchestration. Never use `.unwrap()` or `.expect()` in non-test production paths.
3. **Safety First**: Every termination path must validate against `crate::safety::SafetyShield`. Never call shell commands to kill processes.
4. **Credential Privacy**: Never log or print unmasked environment variables or user secrets.
5. **No Polling Loops**: Avoid tight CPU polling loops. Use event-driven channels and monotonic tick rates for UI refreshes.

---

## 3. Adding New AI Agent Signatures

To teach TIMMY how to identify a new AI agent or coding assistant:

1. Navigate to `src/engine/attribution.rs`.
2. Add a new `AgentSignature` entry with:
   - `name`: Display name of the agent (e.g., `"Devin"`, `"Aider"`, `"OpenDevin"`).
   - `binary_names`: Known executables (e.g., `["aider", "aider-chat"]`).
   - `cmdline_patterns`: Substrings frequently found in command line invocations.
   - `env_var_markers`: Characteristic environment variables injected by the tool.
   - `default_confidence`: Confidence level (`Confirmed` or `HighConfidence`).
3. Add a corresponding test in `tests/attribution_tests.rs` or the unit test block in `src/engine/attribution.rs`.

---

## 4. Submitting Pull Requests

1. Fork the repository and create a descriptive branch:
   ```bash
   git checkout -b feat/add-copilot-agent-signature
   ```
2. Commit your changes with clear commit messages following conventional commits:
   - `feat: ...` for new features
   - `fix: ...` for bug fixes
   - `docs: ...` for documentation
   - `refactor: ...` for internal structural improvements
3. Push to your fork and submit a Pull Request against `main`.
4. Ensure all CI checks pass.
