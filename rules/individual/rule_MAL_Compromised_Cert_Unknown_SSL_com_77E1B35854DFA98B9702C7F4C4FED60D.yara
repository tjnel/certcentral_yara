import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_77E1B35854DFA98B9702C7F4C4FED60D {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-30"
      version             = "1.0"

      hash                = "fbd914b7d9019785d62c25ad164901752c5587c0847e32598e66fa25b6cf23cb"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "TECH SOLUTIONS BHAM INC."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "77:e1:b3:58:54:df:a9:8b:97:02:c7:f4:c4:fe:d6:0d"
      cert_thumbprint     = "8BDF9C2CC3E1D7E917DE1D0A123029066FB88DEE"
      cert_valid_from     = "2024-10-30"
      cert_valid_to       = "2025-10-30"

      country             = "US"
      state               = "Alabama"
      locality            = "Birmingham"
      email               = "???"
      rdn_serial_number   = "000-826-105"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "77:e1:b3:58:54:df:a9:8b:97:02:c7:f4:c4:fe:d6:0d"
      )
}
