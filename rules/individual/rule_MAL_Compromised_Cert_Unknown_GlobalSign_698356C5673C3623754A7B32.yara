import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_698356C5673C3623754A7B32 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-16"
      version             = "1.0"

      hash                = "1fb476adf16b82864b25730f380ee59c795c74f7dbcb14a1da2d7276af593a73"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Wuhan Linhuizhang Trading Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "69:83:56:c5:67:3c:36:23:75:4a:7b:32"
      cert_thumbprint     = "3B81CB00B463DF66F04FE7414B43798A060D50F2"
      cert_valid_from     = "2025-05-16"
      cert_valid_to       = "2026-05-17"

      country             = "CN"
      state               = "Hubei"
      locality            = "Wuhan"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "69:83:56:c5:67:3c:36:23:75:4a:7b:32"
      )
}
