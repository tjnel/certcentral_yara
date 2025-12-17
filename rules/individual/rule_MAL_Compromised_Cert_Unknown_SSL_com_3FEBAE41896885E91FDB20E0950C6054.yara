import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_3FEBAE41896885E91FDB20E0950C6054 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-13"
      version             = "1.0"

      hash                = "bd21360149904ce42c6927d9c3fb482316f2537a4a7bce8b64990428e27a54ac"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ECHO INFINI SDN. BHD."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "3f:eb:ae:41:89:68:85:e9:1f:db:20:e0:95:0c:60:54"
      cert_thumbprint     = "29338264019B62D11F9C6C4B5A69B78B899B4DF6"
      cert_valid_from     = "2025-01-13"
      cert_valid_to       = "2027-01-13"

      country             = "MY"
      state               = "Johor"
      locality            = "Skudai"
      email               = "???"
      rdn_serial_number   = "202401031184"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "3f:eb:ae:41:89:68:85:e9:1f:db:20:e0:95:0c:60:54"
      )
}
