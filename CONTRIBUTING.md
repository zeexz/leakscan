# Contributing to `leakscan`

Thank you for your interest in improving `leakscan`! We welcome contributions from the community to help identify new secret patterns, optimize scan performance, and harden security.

---

## 🛠️ Development Setup

### Prerequisites
- **Go 1.22+** (Go 1.24+ recommended)
- **Git**

### Clone & Build

```bash
git clone https://github.com/zeexz/secret-leak-scanner.git
cd secret-leak-scanner

# Install dependencies
go mod download

# Build local binary
go build -o leakscan main.go

# Run tests
go test -v ./...
```

---

## 🧩 Adding New Detection Rules

Default secret signatures are declared in [`rules/default-patterns.yaml`](rules/default-patterns.yaml).

When adding a new pattern rule:
1. Provide a unique `id` and descriptive `name`.
2. Ensure regular expressions use non-capturing or strictly bounded matching where appropriate to minimize false positives.
3. Assign an appropriate `severity` (`critical`, `high`, `medium`, `low`).
4. Include actionable `remediation` advice.
5. Add unit test test cases in [`internal/detector/regex_test.go`](internal/detector/regex_test.go) verifying both true positives and false positive rejections.

Example entry:
```yaml
- id: example-service-token
  name: Example Service API Key
  description: API token for Example Cloud Services
  pattern: "(?i)ex_live_[0-9a-zA-Z]{32}"
  severity: critical
  remediation: Revoke the leaked key immediately in Example Cloud Console.
```

---

## 🧪 Testing Guidelines

Run the test suite across all packages:

```bash
# Run all unit tests
go test -race ./...

# Run detector tests with coverage
go test -cover ./internal/detector/...
```

---

## 📋 Pull Request Process

1. Fork the repository and create your feature branch: `git checkout -b feat/new-rule-aws-session`.
2. Ensure all tests pass and code is formatted with `go fmt ./...`.
3. Commit your changes with clear, descriptive commit messages.
4. Push to your branch and submit a Pull Request describing your changes.

---

## 🔒 Reporting Security Vulnerabilities

Please **do not** report security vulnerabilities via public GitHub issues. Use [GitHub Private Vulnerability Reporting](https://github.com/zeexz/secret-leak-scanner/security/advisories/new) or contact the maintainers directly.
