import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_19EB62BE9CF0E4C6A8FDA991 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-17"
      version             = "1.0"

      hash                = "8d3fbb350621ac0db0bcaeef0efd4ef8240a0fd242271a59e8b9a7d2069ff80a"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Tester Software Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "19:eb:62:be:9c:f0:e4:c6:a8:fd:a9:91"
      cert_thumbprint     = "0A99B6669B8AADC65A12456DF4AD8549E8084675"
      cert_valid_from     = "2025-01-17"
      cert_valid_to       = "2026-01-18"

      country             = "CN"
      state               = "Liaoning"
      locality            = "Dalian"
      email               = "???"
      rdn_serial_number   = "91210231MA107A346U"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "19:eb:62:be:9c:f0:e4:c6:a8:fd:a9:91"
      )
}
