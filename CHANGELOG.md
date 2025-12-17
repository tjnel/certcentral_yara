# Changelog

All notable changes to the CertGraveyard YARA rules will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [2025.12.17] - 2025-12-17

### Added
- MAL_Compromised_Cert_ZhongStealer_Sectigo_22705DBF157ED535146911BAADB3B64A (ZhongStealer - Sectigo)
- MAL_Compromised_Cert_UNK_50_Microsoft_330005C28FC1E398D5899CAFC500000005C28F (UNK-50 - Microsoft)
- MAL_Compromised_Cert_UNK_50_Microsoft_330006B17881564C863F9CFE9900000006B178 (UNK-50 - Microsoft)
- MAL_Compromised_Cert_NetSupport_RAT_GlobalSign_3F4C9B98FD5FBBFF44B8A012 (NetSupport RAT - GlobalSign)

### Modified
- MAL_Compromised_Cert_ScreenConnectLoader_Sectigo_4E3DC08BA3B230C5968A4C8B6B1B3C64 (Updated metadata for ScreenConnectLoader)

## [Unreleased]

### Checked 2025-12-16
- No new certificates detected

### Checked 2025-12-16
- No new certificates detected

### Added
- Initial release of CertGraveyard YARA Rules Generator
- Automated CSV download from CertGraveyard API
- YARA rule generation for compromised certificates
- Rule validation with yara-python
- CLI interface with Typer
- GitHub Actions workflows for daily updates and releases
