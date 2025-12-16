import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_0B3C5F51042466CBB5A00EE692614668 {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-01"
      version             = "1.0"

      hash                = "aed717381cc8b42276cbbf2d702be4395cebcbecb3b823b3f7ac98dd92bf68dc"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Ordinal Soft Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "0b:3c:5f:51:04:24:66:cb:b5:a0:0e:e6:92:61:46:68"
      cert_thumbprint     = "72BBB1470BDD449901E2A2FD109337B21756C45B"
      cert_valid_from     = "2024-06-01"
      cert_valid_to       = "2025-06-01"

      country             = "GB"
      state               = "???"
      locality            = "West Drayton"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "0b:3c:5f:51:04:24:66:cb:b5:a0:0e:e6:92:61:46:68"
      )
}
