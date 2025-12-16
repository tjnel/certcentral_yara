import "pe"

rule MAL_Compromised_Cert_RemcosRAT_SSL_com_009D9EDAE470A7D76B8B0F1792232D83 {
   meta:
      description         = "Detects RemcosRAT with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-24"
      version             = "1.0"

      hash                = "8337a4fa2d982a4b4a544b71715c8d79a97278113b887a7fcce111719e0fba4a"
      malware             = "RemcosRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Annett Holdings, Inc."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "00:9d:9e:da:e4:70:a7:d7:6b:8b:0f:17:92:23:2d:83"
      cert_thumbprint     = "FB0B1115DF46E050E3DE833233730180987ED386"
      cert_valid_from     = "2025-07-24"
      cert_valid_to       = "2026-07-18"

      country             = "US"
      state               = "Iowa"
      locality            = "Des Moines"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "00:9d:9e:da:e4:70:a7:d7:6b:8b:0f:17:92:23:2d:83"
      )
}
