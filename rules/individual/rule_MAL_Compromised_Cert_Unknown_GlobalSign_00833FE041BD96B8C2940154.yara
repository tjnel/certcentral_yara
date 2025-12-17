import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_00833FE041BD96B8C2940154 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-12"
      version             = "1.0"

      hash                = "1c359c389129097bfcf8fe7a4cde1c20686b76f12a9a095667b85c3c02030006"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "BLACK INDIGO LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "00:83:3f:e0:41:bd:96:b8:c2:94:01:54"
      cert_thumbprint     = "9A4D87370D9184C85A98885BD928D34DC6AA38D5"
      cert_valid_from     = "2024-11-12"
      cert_valid_to       = "2025-11-13"

      country             = "IL"
      state               = "Central District"
      locality            = "Ra'anana"
      email               = "???"
      rdn_serial_number   = "515530624"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "00:83:3f:e0:41:bd:96:b8:c2:94:01:54"
      )
}
