import "pe"

rule MAL_Compromised_Cert_SnipBot_GlobalSign_209B10989A2B18672B29C1C8 {
   meta:
      description         = "Detects SnipBot with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-01-25"
      version             = "1.0"

      hash                = "5b30a5b71ef795e07c91b7a43b3c1113894a82ddffc212a2fa71eebc078f5118"
      malware             = "SnipBot"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "KHAROS LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "20:9b:10:98:9a:2b:18:67:2b:29:c1:c8"
      cert_thumbprint     = "38FAAB8CE29D79CA90AA64179C559F683245D774"
      cert_valid_from     = "2024-01-25"
      cert_valid_to       = "2025-01-25"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "20:9b:10:98:9a:2b:18:67:2b:29:c1:c8"
      )
}
