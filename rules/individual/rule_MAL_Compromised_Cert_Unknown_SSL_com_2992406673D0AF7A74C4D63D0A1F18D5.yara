import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_2992406673D0AF7A74C4D63D0A1F18D5 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-27"
      version             = "1.0"

      hash                = "55a555ab3d3420d8e6f20bb22d4ed4614d6bbb2c64c30479a1673a130b06d746"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LIFECLUE SOLUTIONS PRIVATE LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "29:92:40:66:73:d0:af:7a:74:c4:d6:3d:0a:1f:18:d5"
      cert_thumbprint     = "9E2D9588645D2DB1D7C52861AEA02470E99D792B"
      cert_valid_from     = "2025-08-27"
      cert_valid_to       = "2026-08-27"

      country             = "IN"
      state               = "Haryana"
      locality            = "Rewari"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "29:92:40:66:73:d0:af:7a:74:c4:d6:3d:0a:1f:18:d5"
      )
}
