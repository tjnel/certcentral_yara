import "pe"

rule MAL_Compromised_Cert_Mofongoloader_GlobalSign_4D6069B50525633949C12B22 {
   meta:
      description         = "Detects Mofongoloader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-06-01"
      version             = "1.0"

      hash                = "6b0ce8e6ccab57ece76302b1c9ab570336f63bae4d11137ccf0b662fa323a457"
      malware             = "Mofongoloader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "OOO BASIS"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "4d:60:69:b5:05:25:63:39:49:c1:2b:22"
      cert_thumbprint     = "F81BB0C6DCC4ED1FC06A7004D0A7A636B42013A5"
      cert_valid_from     = "2023-06-01"
      cert_valid_to       = "2024-04-19"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1227700563133"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "4d:60:69:b5:05:25:63:39:49:c1:2b:22"
      )
}
