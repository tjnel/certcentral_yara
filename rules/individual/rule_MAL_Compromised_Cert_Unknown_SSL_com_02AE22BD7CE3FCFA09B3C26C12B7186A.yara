import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_02AE22BD7CE3FCFA09B3C26C12B7186A {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-11"
      version             = "1.0"

      hash                = "f5b31bd394e0a3adb6bd175207b8c3ccc51850c8f2cee1149a8421736168e13e"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SAVAGE CABBAGE SOFTWARE PTY LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "02:ae:22:bd:7c:e3:fc:fa:09:b3:c2:6c:12:b7:18:6a"
      cert_thumbprint     = "2506E83827CC24528284D178A5E6517456DC6B6E"
      cert_valid_from     = "2025-04-11"
      cert_valid_to       = "2026-04-11"

      country             = "AU"
      state               = "Western Australia"
      locality            = "Kelmscott"
      email               = "???"
      rdn_serial_number   = "136 400 327"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "02:ae:22:bd:7c:e3:fc:fa:09:b3:c2:6c:12:b7:18:6a"
      )
}
