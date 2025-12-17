import "pe"

rule MAL_Compromised_Cert_PDFSkills_GlobalSign_1FA2242655ADC212D505871A {
   meta:
      description         = "Detects PDFSkills with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-18"
      version             = "1.0"

      hash                = "f1773b399bbcfb8656c9ae9dd8f7a79c281ab04c4127e8cb8376400f45dd22be"
      malware             = "PDFSkills"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Impresan Solutions OÜ"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "1f:a2:24:26:55:ad:c2:12:d5:05:87:1a"
      cert_thumbprint     = "f8c955ff0a96b06f90b6b8750cd4cb1b15c90cfe"
      cert_valid_from     = "2025-07-18"
      cert_valid_to       = "2026-07-19"

      country             = "EE"
      state               = "Harju maakond"
      locality            = "Tallinn"
      email               = "impresansolutions@gmail.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "1f:a2:24:26:55:ad:c2:12:d5:05:87:1a"
      )
}
