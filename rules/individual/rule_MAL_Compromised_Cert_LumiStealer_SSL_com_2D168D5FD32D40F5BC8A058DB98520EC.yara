import "pe"

rule MAL_Compromised_Cert_LumiStealer_SSL_com_2D168D5FD32D40F5BC8A058DB98520EC {
   meta:
      description         = "Detects LumiStealer with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-21"
      version             = "1.0"

      hash                = "c9d8c91666f3b7c1c1e4c3f1ebfef5a26d6c7cbcbed21d70dcd830cf718f4518"
      malware             = "LumiStealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "RAFAEL RIBEIRO GONÇALVES"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "2d:16:8d:5f:d3:2d:40:f5:bc:8a:05:8d:b9:85:20:ec"
      cert_thumbprint     = "5CEF79491CE85B150098532E0FC46543820CF38F"
      cert_valid_from     = "2025-07-21"
      cert_valid_to       = "2026-07-21"

      country             = "BR"
      state               = "São Paulo"
      locality            = "São Paulo"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "2d:16:8d:5f:d3:2d:40:f5:bc:8a:05:8d:b9:85:20:ec"
      )
}
