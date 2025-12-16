import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_4D0E13F913C4C8BB5753B53DB46110F0 {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-01"
      version             = "1.0"

      hash                = "1f3f3fb0afe19c7c8ce7918c5d1c82be07b17ac346677c84cb5aa5bc9090171b"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Manas Softwares Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "4d:0e:13:f9:13:c4:c8:bb:57:53:b5:3d:b4:61:10:f0"
      cert_thumbprint     = "8AB0BE341C5E80501E70775A5CFD24D945595568"
      cert_valid_from     = "2024-05-01"
      cert_valid_to       = "2025-05-01"

      country             = "GB"
      state               = "England"
      locality            = "Slough"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "4d:0e:13:f9:13:c4:c8:bb:57:53:b5:3d:b4:61:10:f0"
      )
}
