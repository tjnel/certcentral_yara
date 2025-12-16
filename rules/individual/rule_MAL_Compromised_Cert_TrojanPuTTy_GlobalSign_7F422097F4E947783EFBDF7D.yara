import "pe"

rule MAL_Compromised_Cert_TrojanPuTTy_GlobalSign_7F422097F4E947783EFBDF7D {
   meta:
      description         = "Detects TrojanPuTTy with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-25"
      version             = "1.0"

      hash                = "650d8b95e4fe29336c53d3d4b7d67375743cf9a32fe7630447cd48a7682e06f8"
      malware             = "TrojanPuTTy"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "PUSHYAMITR SECURITY SERVICE PRIVATE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7f:42:20:97:f4:e9:47:78:3e:fb:df:7d"
      cert_thumbprint     = "39700A1B0CCFA238054E1C6D96298A8E9158D8E6"
      cert_valid_from     = "2025-06-25"
      cert_valid_to       = "2026-06-26"

      country             = "IN"
      state               = "Bihar"
      locality            = "Muzaffarpur"
      email               = "dhirajpss2018@gmail.com"
      rdn_serial_number   = "U74999BR2018PTC037680"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7f:42:20:97:f4:e9:47:78:3e:fb:df:7d"
      )
}
