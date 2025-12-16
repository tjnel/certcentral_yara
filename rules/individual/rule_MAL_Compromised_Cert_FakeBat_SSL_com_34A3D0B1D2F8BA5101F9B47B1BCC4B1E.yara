import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_34A3D0B1D2F8BA5101F9B47B1BCC4B1E {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-17"
      version             = "1.0"

      hash                = "e8de3d58f329400152c70f395d4bea2991841a91c3a35a3bec5dfc08a2057078"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Rfrsh Creative Inc."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "34:a3:d0:b1:d2:f8:ba:51:01:f9:b4:7b:1b:cc:4b:1e"
      cert_thumbprint     = "201CD26069D568B0647206AADFBD3793F0C84918"
      cert_valid_from     = "2024-05-17"
      cert_valid_to       = "2025-05-17"

      country             = "CA"
      state               = "Quebec"
      locality            = "Dollard-Des Ormeaux"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "34:a3:d0:b1:d2:f8:ba:51:01:f9:b4:7b:1b:cc:4b:1e"
      )
}
