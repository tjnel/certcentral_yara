# CertCentral YARA Rules Generator

[![CI](https://github.com/tjnel/cert-central-yara/actions/workflows/ci.yml/badge.svg)](https://github.com/tjnel/cert-central-yara/actions/workflows/ci.yml)
[![Daily Update](https://github.com/tjnel/cert-central-yara/actions/workflows/daily-update.yml/badge.svg)](https://github.com/tjnel/cert-central-yara/actions/workflows/daily-update.yml)

Automated YARA rule generation from the [CertCentral](https://certcentral.org) compromised certificate database.

## Features

- 🔄 **Daily Updates**: Automatically checks CertCentral for new compromised certificates
- 📝 **YARA Rule Generation**: Creates individual YARA rules for each certificate
- ✅ **Validation**: Validates all rules with yara-python
- 📦 **Release Management**: Automated releases with combined ruleset and ZIP archive
- 📋 **Changelog**: Maintains detailed changelog of all additions and modifications

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/tjnel/cert-central-yara.git
cd cert-central-yara

# Install with UV
uv sync --all-extras
```

### Usage

```bash
# Download latest CSV from CertCentral
cert-central-yara download

# Check if CSV has changed
cert-central-yara check-changed

# Generate YARA rules
cert-central-yara generate

# Validate rules
cert-central-yara validate --engine yara

# Create combined file and ZIP archive
cert-central-yara combine
cert-central-yara package

# Run full pipeline
cert-central-yara run --all
```

### Using the Generated Rules

Download the latest release or use the rules directly:

```bash
# Scan with combined ruleset
yara rules/combined/MAL_Compromised_Cert_*.yara /path/to/scan

# Or use individual rules
yara rules/individual/*.yara /path/to/scan
```

## Project Structure

```
cert-central-yara/
├── .github/workflows/      # GitHub Actions
│   ├── daily-update.yml    # Daily CSV check and rule generation
│   ├── ci.yml              # PR validation and testing
│   └── release.yml         # Release creation
├── src/cert_central_yara/  # Source code
│   ├── __init__.py
│   ├── downloader.py       # CSV download and caching
│   ├── parser.py           # CSV parsing
│   ├── generator.py        # YARA rule generation
│   ├── validator.py        # Rule validation
│   ├── changelog.py        # Changelog management
│   └── cli.py              # Command-line interface
├── tests/                  # Test suite
├── rules/
│   ├── individual/         # Individual YARA rule files
│   └── combined/           # Combined release files
├── data/                   # CSV data and hash files
├── templates/              # Jinja2 templates
└── CHANGELOG.md
```

## Generated Rule Format

Each rule follows this format:

```yara
import "pe"

rule MAL_Compromised_Cert_Emotet_DigiCert_0a_1b_2c_3d {
   meta:
      description         = "Detects malware Emotet using compromised certificate..."
      author              = "CertCentral-YARA-Generator"
      reference           = "https://certcentral.org"
      
      hash                = "a1b2c3d4..."
      malware             = "Emotet"
      malware_type        = "Trojan"
      
      cert_issuer         = "DigiCert SHA2 Assured ID Code Signing CA"
      cert_serial         = "0a:1b:2c:3d"
      cert_valid_from     = "2024-01-15"
      cert_valid_to       = "2025-01-15"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert SHA2 Assured ID Code Signing CA" and
         sig.serial == "0a:1b:2c:3d"
      )
}
```

## Development

### Setup Development Environment

```bash
# Install with dev dependencies
uv sync --all-extras

# Run linting
uv run ruff check src tests

# Run type checking
uv run mypy src

# Run tests
uv run pytest
```

### Running Tests

```bash
# Run all tests with coverage
uv run pytest

# Run specific test file
uv run pytest tests/test_generator.py

# Run with verbose output
uv run pytest -v
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `download` | Download CSV from CertCentral |
| `check-changed` | Check if CSV has changed since last run |
| `generate` | Generate YARA rules from CSV |
| `validate` | Validate YARA rules |
| `changelog` | Update changelog with changes |
| `combine` | Create combined YARA file |
| `package` | Create ZIP archive of rules |
| `run` | Run full pipeline |

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CERTCENTRAL_URL` | CSV download URL | `https://certcentral.org/api/download_csv` |

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [CertCentral](https://certcentral.org) for providing the compromised certificate database
- [YARA](https://virustotal.github.io/yara/) for the pattern matching engine

