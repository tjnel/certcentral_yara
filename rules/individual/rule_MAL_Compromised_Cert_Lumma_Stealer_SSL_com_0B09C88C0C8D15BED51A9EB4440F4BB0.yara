import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_SSL_com_0B09C88C0C8D15BED51A9EB4440F4BB0 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-03"
      version             = "1.0"

      hash                = "de6fcdf58b22a51d26eacb0e2c992d9a894c1894b3c8d70f4db80044dacb7430"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "VERANDAH GREEN LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "0b:09:c8:8c:0c:8d:15:be:d5:1a:9e:b4:44:0f:4b:b0"
      cert_thumbprint     = "561620A3F0BF4FB96898A99252B85B00C468E5AF"
      cert_valid_from     = "2024-12-03"
      cert_valid_to       = "2025-11-29"

      country             = "GB"
      state               = "???"
      locality            = "Hook"
      email               = "???"
      rdn_serial_number   = "12979554"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "0b:09:c8:8c:0c:8d:15:be:d5:1a:9e:b4:44:0f:4b:b0"
      )
}
