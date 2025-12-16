import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Sectigo_008B3F8F725F80DECBDB4920ADA8817F3A {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-03-21"
      version             = "1.0"

      hash                = "f9ebdee82173f0cd71a90d189d89947952e23756651da241d675328616a35ea2"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware leverages cloud hosting to hold additional components. The components are TASLogin and its associated DLL: medium.com/@anyrun/zhong-stealer-analysis-new-malware-targeting-fintech-and-cryptocurrency-71d4a3cce42c"

      signer              = "BLOOMTECHNOLOGY.INC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:8b:3f:8f:72:5f:80:de:cb:db:49:20:ad:a8:81:7f:3a"
      cert_thumbprint     = "70C5CF27162A4EE6305CE63E53C948411C3EDC28"
      cert_valid_from     = "2023-03-21"
      cert_valid_to       = "2026-03-20"

      country             = "KR"
      state               = "Gyeonggi-do"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:8b:3f:8f:72:5f:80:de:cb:db:49:20:ad:a8:81:7f:3a"
      )
}
