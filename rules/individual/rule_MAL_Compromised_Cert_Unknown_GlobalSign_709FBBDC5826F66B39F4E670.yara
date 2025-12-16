import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_709FBBDC5826F66B39F4E670 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-13"
      version             = "1.0"

      hash                = "a562994ad72896f6112491f041bae45e0d7bd9c8809400a3071c42b336b87a39"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "meta.team1337@gmail.com"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R6 SMIME CA 2023"
      cert_serial         = "70:9f:bb:dc:58:26:f6:6b:39:f4:e6:70"
      cert_thumbprint     = "97691BA8845459205E344D5FA5AD7C9DD5F64850"
      cert_valid_from     = "2025-04-13"
      cert_valid_to       = "2026-04-14"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "meta.team1337@gmail.com"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R6 SMIME CA 2023" and
         sig.serial == "70:9f:bb:dc:58:26:f6:6b:39:f4:e6:70"
      )
}
