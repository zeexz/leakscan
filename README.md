# leakscan — Env Var & Secrets Leak Scanner CLI

`leakscan` is a zero-leak security CLI tool written in **Go** that scans local filesystems, git commit histories, shell logs, and active process environments for exposed credentials, API keys, tokens, and private keys.

---

## Key Features

- 🔒 **Zero Secret Leak Guarantee**: All secret values in terminal output, log streams, and JSON reports are redacted by default (`AKIA****************ABCD` or `[REDACTED]`).
- 📁 **Filesystem Scanner**: Walk project directories inspecting `.env*`, `.aws/credentials`, SSH keys, and dotfiles. Detects insecure world-readable file permissions.
- 📜 **Git History Scanner**: Inspect every historical commit tree using `go-git` to find deleted or historical secret leaks.
- 🐚 **Shell History Scanner**: Scan `~/.bash_history`, `~/.zsh_history`, and `$HISTFILE` for inline command secrets.
- ⚡ **Entropy-based Detection**: Calculate Shannon entropy ($H(X) = -\sum p \log_2 p$) to flag unknown, high-randomness API keys and tokens while suppressing placeholders.
- ⚙️ **CI / Pre-commit Hook Integration**: Supports `--format json` and configurable `--fail-severity` exit codes for pipeline gates.

---

## Installation & Quick Start

### ⚡ Quick Install (Recommended)

**Windows** (PowerShell):
```powershell
iex (irm https://raw.githubusercontent.com/YOUR_USERNAME/leakscan/main/install.ps1)
```

**macOS / Linux**:
```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/leakscan/main/install.sh | bash
```

> **Note:** Replace `YOUR_USERNAME` with your actual GitHub username once your repo is published. The scripts auto-detect your OS and architecture, download the latest release binary, and add `leakscan` to your PATH.

### Build from Source
Requires Go 1.22+:

```bash
git clone https://github.com/YOUR_USERNAME/leakscan.git
cd leakscan
go build -o leakscan main.go
```

### Basic Usage

#### 1. Interactive LazyVim TUI Dashboard
```bash
go run main.go tui .
```

#### 2. Scan Local Directory (LazyVim Styled Output)
```bash
go run main.go scan .
```

#### 3. Scan Directory Including Full Git History
```bash
go run main.go scan --include-git-history .
```

#### 4. Scan Shell History & Process Environment
```bash
go run main.go scan --include-shell-history --include-process-env .
```

#### 5. JSON Output for CI/CD Pipelines
```bash
go run main.go scan --format json --fail-severity high .
```

#### 6. Initialize Pre-Commit Hook & Ignore File
```bash
go run main.go init
```

#### 7. Live Directory Monitoring
```bash
go run main.go watch .
```

---

## Design Decisions

1. **Layered Detection Engine (Regex + Shannon Entropy)**
   Known secrets (AWS keys, GitHub tokens, Slack tokens, SSH private keys) have distinct deterministic prefixes matched via Regex rules. Unknown or custom API keys are caught via Shannon Entropy scoring ($H(X) \ge 3.8$) combined with variable name heuristic analysis, avoiding false positives by filtering placeholders (`your-key-here`, `CHANGEME`).

2. **Redaction-by-Default**
   A security scanner must never become a vector for secret exposure. Raw secret values are processed in memory and masked immediately. Up to 4 leading and trailing characters are preserved for identification context, with mid-sections replaced by masking stars (`*`).

3. **Fully Local Execution & Zero Telemetry**
   `leakscan` performs zero external network calls, collects no telemetry, and requires no API keys or third-party cloud services. All analysis occurs locally on your machine.

---

## Threat Model

### What `leakscan` Catches
- Plain-text secrets committed to source files (`.env`, `.json`, `.yaml`, `.py`, `.go`).
- Forgotten credentials remaining in git commit history (even after file deletion).
- Environment variable exports recorded in shell history logs.
- Insecure world-readable file permissions on local credential files (`chmod 644 .env`).
- Exposed environment variables in running process inspectable on multi-user systems.

### What `leakscan` Explicitly Does NOT Catch
- **Already Exfiltrated Secrets**: `leakscan` is a defensive hygiene scanner; it cannot determine if an attacker has already exfiltrated a secret.
- **Out-of-Band Memory / Heap Leaks**: Does not inspect raw RAM process heaps or swap space.
- **Obfuscated / Encrypted Secrets**: High-entropy strings encrypted with standard ciphers are treated as ciphertext unless variable naming indicates credentials.

---

## License
MIT License.
