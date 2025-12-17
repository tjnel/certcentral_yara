import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_7AB605B1E1AB02C04422CE5490977D20 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-16"
      version             = "1.0"

      hash                = "6c004d89d657f58f5ecf1367288e2af8e264f62429d3b7115be116403eb1b2c6"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ELLEN SOFTWARE SOLUTIONS LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "7a:b6:05:b1:e1:ab:02:c0:44:22:ce:54:90:97:7d:20"
      cert_thumbprint     = "2BB20F82B61B7AE5A4A2526017A247792A0BFAC2"
      cert_valid_from     = "2024-12-16"
      cert_valid_to       = "2025-12-16"

      country             = "GB"
      state               = "???"
      locality            = "Bath"
      email               = "???"
      rdn_serial_number   = "11508460"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "7a:b6:05:b1:e1:ab:02:c0:44:22:ce:54:90:97:7d:20"
      )
}
