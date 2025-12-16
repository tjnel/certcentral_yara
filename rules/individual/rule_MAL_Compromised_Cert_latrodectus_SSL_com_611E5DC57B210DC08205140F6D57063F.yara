import "pe"

rule MAL_Compromised_Cert_latrodectus_SSL_com_611E5DC57B210DC08205140F6D57063F {
   meta:
      description         = "Detects latrodectus with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-11"
      version             = "1.0"

      hash                = "87c787ea53a4dad92afd36c13a4fc5da7af1ea8dbe5634e4e3b011f289c9c91b"
      malware             = "latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ASTRA PROPERTY MANAGEMENT, SRL"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA ECC R2"
      cert_serial         = "61:1e:5d:c5:7b:21:0d:c0:82:05:14:0f:6d:57:06:3f"
      cert_thumbprint     = "6ed1e4c622f0ddb484716df01b3cde1781181c45c07fac22eebc07e7ba8559c3"
      cert_valid_from     = "2025-08-11"
      cert_valid_to       = "2026-08-11"

      country             = "MD"
      state               = "Bălți Municipality"
      locality            = "Bălţi"
      email               = "???"
      rdn_serial_number   = "1017602002645"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA ECC R2" and
         sig.serial == "61:1e:5d:c5:7b:21:0d:c0:82:05:14:0f:6d:57:06:3f"
      )
}
