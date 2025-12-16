import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_GlobalSign_2F93FA58F00445EEDC313273 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-22"
      version             = "1.0"

      hash                = "16e01dd4c60462c0a870bf55ec987514e122f27b306858e73f71a8ca4b896423"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware leverages cloud hosting to hold additional components. The components are TASLogin and its associated DLL: medium.com/@anyrun/zhong-stealer-analysis-new-malware-targeting-fintech-and-cryptocurrency-71d4a3cce42c"

      signer              = "Chengdu Nuoxin Times Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "2f:93:fa:58:f0:04:45:ee:dc:31:32:73"
      cert_thumbprint     = "3CF1146EDC6B0C3595D5C8C015BF52E77BA1C74C"
      cert_valid_from     = "2025-04-22"
      cert_valid_to       = "2026-08-14"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Chengdu"
      email               = "???"
      rdn_serial_number   = "91510100MA65214R21"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "2f:93:fa:58:f0:04:45:ee:dc:31:32:73"
      )
}
