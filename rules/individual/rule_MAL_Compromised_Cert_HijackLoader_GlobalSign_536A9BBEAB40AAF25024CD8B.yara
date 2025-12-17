import "pe"

rule MAL_Compromised_Cert_HijackLoader_GlobalSign_536A9BBEAB40AAF25024CD8B {
   meta:
      description         = "Detects HijackLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-03"
      version             = "1.0"

      hash                = "7dc2ddaac0f6c54d774f6b336fa15a249fd0d5e74a903e7ada07cc00772c8341"
      malware             = "HijackLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC GrandStroy"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "53:6a:9b:be:ab:40:aa:f2:50:24:cd:8b"
      cert_thumbprint     = "29EB40C0EFE05D01210D6F3197F854E214CB5A3B"
      cert_valid_from     = "2025-06-03"
      cert_valid_to       = "2026-06-04"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1091103000922"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "53:6a:9b:be:ab:40:aa:f2:50:24:cd:8b"
      )
}
