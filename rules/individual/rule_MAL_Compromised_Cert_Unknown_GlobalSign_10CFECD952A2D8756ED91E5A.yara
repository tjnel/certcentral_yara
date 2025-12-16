import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_10CFECD952A2D8756ED91E5A {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-15"
      version             = "1.0"

      hash                = "84f34f24a7f7852ac1c5e99ec3de6e215138d7b8a39514963dc6596945b105d8"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC GRAN"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "10:cf:ec:d9:52:a2:d8:75:6e:d9:1e:5a"
      cert_thumbprint     = "3A28A14AAAB7EAA8850141AACE5249C1871F9B02"
      cert_valid_from     = "2025-04-15"
      cert_valid_to       = "2026-04-16"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "10:cf:ec:d9:52:a2:d8:75:6e:d9:1e:5a"
      )
}
