import "pe"

rule MAL_Compromised_Cert_RomCom_GlobalSign_2B36039344664935BC7DB613 {
   meta:
      description         = "Detects RomCom with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-11"
      version             = "1.0"

      hash                = "d99788669cdc088c8935d64961332d5ad5cfee4fd71ff1f2115078f4340a6a99"
      malware             = "RomCom"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "APPRAISAL PHARMACEUTICALS (OPC) PRIVATE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "2b:36:03:93:44:66:49:35:bc:7d:b6:13"
      cert_thumbprint     = "5238C4815C13F9D26AD6FA46AEC6CC55671CB16E"
      cert_valid_from     = "2025-02-11"
      cert_valid_to       = "2026-02-12"

      country             = "IN"
      state               = "Rajasthan"
      locality            = "Jaipur"
      email               = "jonathanfowler47@gmail.com"
      rdn_serial_number   = "U24232RJ2014OPC046207"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "2b:36:03:93:44:66:49:35:bc:7d:b6:13"
      )
}
