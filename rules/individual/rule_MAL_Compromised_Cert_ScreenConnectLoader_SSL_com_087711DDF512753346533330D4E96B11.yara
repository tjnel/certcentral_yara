import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_SSL_com_087711DDF512753346533330D4E96B11 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-10"
      version             = "1.0"

      hash                = "3a594ae541ed9700b27fda06d70f83c5f9a6f048d6f08b735d6fcb4b36e49fa6"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Kamal Hoyte"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "08:77:11:dd:f5:12:75:33:46:53:33:30:d4:e9:6b:11"
      cert_thumbprint     = "996CF92B4B761087A8D8B1A6AC0048B32BCB4B8F"
      cert_valid_from     = "2025-06-10"
      cert_valid_to       = "2026-06-10"

      country             = "US"
      state               = "New York"
      locality            = "Freeport"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "08:77:11:dd:f5:12:75:33:46:53:33:30:d4:e9:6b:11"
      )
}
