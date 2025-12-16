import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_31749F1522AB3BDBCB1C05FB6806E40A {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-29"
      version             = "1.0"

      hash                = "b0ade668aef88619166dd49e3b5529dbe2e9f983b599e1d8488113a560dda23a"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Super Creative Oy Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "31:74:9f:15:22:ab:3b:db:cb:1c:05:fb:68:06:e4:0a"
      cert_thumbprint     = "8FBBCDE4D167009F93F0278A18A5D943E0E2C239"
      cert_valid_from     = "2025-08-29"
      cert_valid_to       = "2026-08-29"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Espoo"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "31:74:9f:15:22:ab:3b:db:cb:1c:05:fb:68:06:e4:0a"
      )
}
