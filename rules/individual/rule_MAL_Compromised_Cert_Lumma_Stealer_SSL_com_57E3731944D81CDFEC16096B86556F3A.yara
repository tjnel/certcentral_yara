import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_SSL_com_57E3731944D81CDFEC16096B86556F3A {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-09"
      version             = "1.0"

      hash                = "3a571ea16c1d311ca9b2c914a85726a8cd0bb4f7b0b64d8c1692df59468907ce"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "ETC XD TM DV JOINT STOCK COMPANY"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "57:e3:73:19:44:d8:1c:df:ec:16:09:6b:86:55:6f:3a"
      cert_thumbprint     = "47C8D25B1588303318BBB57ADD579875A4C987DF"
      cert_valid_from     = "2024-11-09"
      cert_valid_to       = "2025-11-08"

      country             = "VN"
      state               = "Hồ Chí Minh City"
      locality            = "Thủ Đức"
      email               = "???"
      rdn_serial_number   = "0317361975"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "57:e3:73:19:44:d8:1c:df:ec:16:09:6b:86:55:6f:3a"
      )
}
