import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_599274D028BD53AF9075E4B5 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-24"
      version             = "1.0"

      hash                = "64b17e0cd6925c7c04ce2fcf8c3ace53c0cbec784e149f56e24a0921add91cf2"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "GI GRAPHIC DESIGN COMPANY LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "59:92:74:d0:28:bd:53:af:90:75:e4:b5"
      cert_thumbprint     = "09FE1BF3DF5AFC60C343A6F71903F656335B3DAB"
      cert_valid_from     = "2024-04-24"
      cert_valid_to       = "2025-04-25"

      country             = "VN"
      state               = "Ha Noi"
      locality            = "Ha Noi"
      email               = "???"
      rdn_serial_number   = "0109733326"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "59:92:74:d0:28:bd:53:af:90:75:e4:b5"
      )
}
