# Changelog

All notable changes to the CertGraveyard YARA rules will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [2025.12.17] - 2025-12-17

### Added
- MAL_Compromised_Cert_UNK_50_Microsoft_330006BD17074683368C2F606300000006BD17 (UNK-50 - Microsoft)
- MAL_Compromised_Cert_ScreenConnectLoader_Sectigo_5886E0F4BAA836E9231BA6F8F965E51D (ScreenConnectLoader - Sectigo)
- MAL_Compromised_Cert_RUS_55_Certum_43CFEE96B948B5B672754F51A0E6E719 (RUS-55 - Certum)

### Modified
- MAL_Compromised_Cert_RUS_55_GlobalSign_65E6B4B9104AFCF9BEE6F984 (Updated metadata for RUS-55)
- MAL_Compromised_Cert_ZhongStealer_Sectigo_22705DBF157ED535146911BAADB3B64A (Updated metadata for ZhongStealer)
- MAL_Compromised_Cert_RUS_55_GlobalSign_5A076B593C5E7DCA24430353 (Updated metadata for RUS-55)

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
