import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_2F2E62C3A8A3A4B85C44D3DF84D6D41A {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-21"
      version             = "1.0"

      hash                = "c98f948bc2965c741c08290a8bdc81e16c8f28f267ad17eb0c42fb9a472fa1cc"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MULTIMEDIOS CORDILLERANOS SRL"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "2f:2e:62:c3:a8:a3:a4:b8:5c:44:d3:df:84:d6:d4:1a"
      cert_thumbprint     = "CD4C578692C6E884980AE1C53E49800107C2D4CA"
      cert_valid_from     = "2025-07-21"
      cert_valid_to       = "2026-07-21"

      country             = "AR"
      state               = "San Juan Province"
      locality            = "San Juan"
      email               = "???"
      rdn_serial_number   = "30-71069624-8"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "2f:2e:62:c3:a8:a3:a4:b8:5c:44:d3:df:84:d6:d4:1a"
      )
}
