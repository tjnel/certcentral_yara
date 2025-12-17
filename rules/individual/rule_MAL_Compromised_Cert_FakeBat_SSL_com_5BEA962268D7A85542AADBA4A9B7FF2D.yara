import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_5BEA962268D7A85542AADBA4A9B7FF2D {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-01-26"
      version             = "1.0"

      hash                = "a1464bece4aa329bb639d2d3ff6c7d5d4d349289cd477c86c669975db4824443"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "JMN Rope Access Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "5b:ea:96:22:68:d7:a8:55:42:aa:db:a4:a9:b7:ff:2d"
      cert_thumbprint     = "C4232291AD05DB6C435CD8A727F4DAF0BF6507D4"
      cert_valid_from     = "2024-01-26"
      cert_valid_to       = "2025-01-25"

      country             = "GB"
      state               = "???"
      locality            = "Alnwick"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "5b:ea:96:22:68:d7:a8:55:42:aa:db:a4:a9:b7:ff:2d"
      )
}
