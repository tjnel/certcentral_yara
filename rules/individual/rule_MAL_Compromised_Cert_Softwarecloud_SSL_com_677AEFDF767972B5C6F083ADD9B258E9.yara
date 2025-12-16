import "pe"

rule MAL_Compromised_Cert_Softwarecloud_SSL_com_677AEFDF767972B5C6F083ADD9B258E9 {
   meta:
      description         = "Detects Softwarecloud with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-02"
      version             = "1.0"

      hash                = "73b69c8ecc07569617d494171529a8f6259948eeea75e4df986042daa4ca3412"
      malware             = "Softwarecloud"
      malware_type        = "Unknown"
      malware_notes       = "This malware is part of a campaign of inauthentic software. More research is likely needed: https://x.com/andrewdanis/status/1919585650413629680?s=20"

      signer              = "Quantum Green Solutions ApS"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "67:7a:ef:df:76:79:72:b5:c6:f0:83:ad:d9:b2:58:e9"
      cert_thumbprint     = "707AB6D991A3011EC1D7761D86C0F79C98832506"
      cert_valid_from     = "2025-07-02"
      cert_valid_to       = "2026-07-02"

      country             = "DK"
      state               = "Capital Region of Denmark"
      locality            = "Copenhagen"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "67:7a:ef:df:76:79:72:b5:c6:f0:83:ad:d9:b2:58:e9"
      )
}
