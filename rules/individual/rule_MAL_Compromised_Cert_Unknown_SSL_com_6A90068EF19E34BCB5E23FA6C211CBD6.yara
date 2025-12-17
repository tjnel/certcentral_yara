import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_6A90068EF19E34BCB5E23FA6C211CBD6 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-18"
      version             = "1.0"

      hash                = "1112b72f47b7d09835c276c412c83d89b072b2f0fb25a0c9e2fed7cf08b55a41"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "THE COMB REIVERS LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA ECC R2"
      cert_serial         = "6a:90:06:8e:f1:9e:34:bc:b5:e2:3f:a6:c2:11:cb:d6"
      cert_thumbprint     = "5B3817E85E23BA9FD84455B18E58B44F476B5909"
      cert_valid_from     = "2025-03-18"
      cert_valid_to       = "2026-03-18"

      country             = "GB"
      state               = "???"
      locality            = "Hexham"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA ECC R2" and
         sig.serial == "6a:90:06:8e:f1:9e:34:bc:b5:e2:3f:a6:c2:11:cb:d6"
      )
}
