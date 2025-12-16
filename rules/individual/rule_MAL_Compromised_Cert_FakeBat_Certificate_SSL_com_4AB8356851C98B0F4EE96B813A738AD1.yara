import "pe"

rule MAL_Compromised_Cert_FakeBat_Certificate_SSL_com_4AB8356851C98B0F4EE96B813A738AD1 {
   meta:
      description         = "Detects FakeBat_Certificate with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-17"
      version             = "1.0"

      hash                = "b9cfc08d3e1d8eae9ba814107b196a55c842d43fa27031278e7463ef05d0aef1"
      malware             = "FakeBat_Certificate"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Asper Research Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "4a:b8:35:68:51:c9:8b:0f:4e:e9:6b:81:3a:73:8a:d1"
      cert_thumbprint     = "F9EF8652D7AAB03E9FBD929CE8C961A200F91662"
      cert_valid_from     = "2024-05-17"
      cert_valid_to       = "2025-05-17"

      country             = "GB"
      state               = "Scotland"
      locality            = "Edinburgh"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "4a:b8:35:68:51:c9:8b:0f:4e:e9:6b:81:3a:73:8a:d1"
      )
}
