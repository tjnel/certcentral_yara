import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_3C16154E4D7DE3DCE12A0030A213491F {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-05"
      version             = "1.0"

      hash                = "db15f45f69f863510986fb2198a8a6b3d55d8ccc8a2ed4bb30bc27bdd1bf151c"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ftechnics, Inc"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "3c:16:15:4e:4d:7d:e3:dc:e1:2a:00:30:a2:13:49:1f"
      cert_thumbprint     = "8ECFB3A1CD45308C84C219A28D202290E0AF5575"
      cert_valid_from     = "2024-09-05"
      cert_valid_to       = "2025-09-14"

      country             = "US"
      state               = "New York"
      locality            = "New York"
      email               = "???"
      rdn_serial_number   = "2990613"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "3c:16:15:4e:4d:7d:e3:dc:e1:2a:00:30:a2:13:49:1f"
      )
}
