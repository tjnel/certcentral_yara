import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_3148B279E3A48C7AE98E868611808C80 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-07"
      version             = "1.0"

      hash                = "5e806486ba11634d071bb202331a804c68bd2612494358408c4227ed0f14b748"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Teapot Software Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "31:48:b2:79:e3:a4:8c:7a:e9:8e:86:86:11:80:8c:80"
      cert_thumbprint     = "1D46B4FB8BAB6EC0185F4312F3ED7C31CACAEB73"
      cert_valid_from     = "2025-01-07"
      cert_valid_to       = "2026-01-07"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Vantaa"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "31:48:b2:79:e3:a4:8c:7a:e9:8e:86:86:11:80:8c:80"
      )
}
