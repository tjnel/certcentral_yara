import "pe"

rule MAL_Compromised_Cert_Donut_SSL_com_01C535271991A4DB65FD3691E04A3512 {
   meta:
      description         = "Detects Donut with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-02"
      version             = "1.0"

      hash                = "93d1f8a756ec37dea2eaabe033f3a28f9d7c7333103e507522cf6492f2ba80b6"
      malware             = "Donut"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CENTRO SOCIAL LUZ DO MUNDO"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "01:c5:35:27:19:91:a4:db:65:fd:36:91:e0:4a:35:12"
      cert_thumbprint     = "1E152A2D0218BC6FF07C379A88C1DBBD5E1F8C63"
      cert_valid_from     = "2025-10-02"
      cert_valid_to       = "2026-10-02"

      country             = "BR"
      state               = "São Paulo"
      locality            = "São Paulo"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "01:c5:35:27:19:91:a4:db:65:fd:36:91:e0:4a:35:12"
      )
}
