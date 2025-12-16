import "pe"

rule MAL_Compromised_Cert_HijackLoader_GlobalSign_16607BC50DD6E4871BEEE868 {
   meta:
      description         = "Detects HijackLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-13"
      version             = "1.0"

      hash                = "cd592cf511b18181bbc9b6cde8dc12c153e8382200ff3194f2ece1bbb328b3ab"
      malware             = "HijackLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "OOO SID"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "16:60:7b:c5:0d:d6:e4:87:1b:ee:e8:68"
      cert_thumbprint     = "BA6BEDE1291C76388B55A5084A73A2CBBAA3404C"
      cert_valid_from     = "2025-08-13"
      cert_valid_to       = "2026-08-14"

      country             = "RU"
      state               = "Saint Petersburg"
      locality            = "Saint Petersburg"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "16:60:7b:c5:0d:d6:e4:87:1b:ee:e8:68"
      )
}
