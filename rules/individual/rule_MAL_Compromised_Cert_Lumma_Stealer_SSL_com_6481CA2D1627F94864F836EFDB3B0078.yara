import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_SSL_com_6481CA2D1627F94864F836EFDB3B0078 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-20"
      version             = "1.0"

      hash                = "7a14e9ee7829dd5c32012637c58963eb07ba78bbc8896ed4e965211e6c7c3034"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "AM MISBAH Tech Inc"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "64:81:ca:2d:16:27:f9:48:64:f8:36:ef:db:3b:00:78"
      cert_thumbprint     = "9DA4300B4923D643659B254B8237352C521C1B23"
      cert_valid_from     = "2024-11-20"
      cert_valid_to       = "2025-11-20"

      country             = "CA"
      state               = "British Columbia"
      locality            = "Surrey"
      email               = "???"
      rdn_serial_number   = "1335546-2"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "64:81:ca:2d:16:27:f9:48:64:f8:36:ef:db:3b:00:78"
      )
}
