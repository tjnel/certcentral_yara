import "pe"

rule MAL_Compromised_Cert_SecTopRAT_ArechClient2_GlobalSign_59F9E96B40B905D435FB78C4 {
   meta:
      description         = "Detects SecTopRAT,ArechClient2 with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-29"
      version             = "1.0"

      hash                = "dc1975e63bec91355246e3b9376b7915749e5240b17e3741047ab69487fdef07"
      malware             = "SecTopRAT,ArechClient2"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "ATOLL LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "59:f9:e9:6b:40:b9:05:d4:35:fb:78:c4"
      cert_thumbprint     = "4E9854568C0EE98C5C70F9E211A0DE2E4A4016A3"
      cert_valid_from     = "2025-01-29"
      cert_valid_to       = "2026-01-30"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1247700776828"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "59:f9:e9:6b:40:b9:05:d4:35:fb:78:c4"
      )
}
