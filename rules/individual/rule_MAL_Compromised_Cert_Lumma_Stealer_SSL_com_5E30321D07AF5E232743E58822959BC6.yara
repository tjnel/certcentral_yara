import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_SSL_com_5E30321D07AF5E232743E58822959BC6 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-05"
      version             = "1.0"

      hash                = "2ada202f6854b6721d931b369736816e809742748dae1d1f26b25a1ff0492464"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "MAGNATE VENTURES LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "5e:30:32:1d:07:af:5e:23:27:43:e5:88:22:95:9b:c6"
      cert_thumbprint     = "8DD688DCB76262393C27E4C5D44D3134E27CEA07"
      cert_valid_from     = "2024-09-05"
      cert_valid_to       = "2025-09-05"

      country             = "KE"
      state               = "???"
      locality            = "Nairobi"
      email               = "???"
      rdn_serial_number   = "C.72799"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "5e:30:32:1d:07:af:5e:23:27:43:e5:88:22:95:9b:c6"
      )
}
