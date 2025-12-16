import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_57B80004869FA005EA8D294906B0A37E {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-12"
      version             = "1.0"

      hash                = "924f4ff9847cf14599576551370779a2f3ca1163100b4f71b94f18d9e1446ab9"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Draco Software Inc."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "57:b8:00:04:86:9f:a0:05:ea:8d:29:49:06:b0:a3:7e"
      cert_thumbprint     = "C8212E991BCAF313DF45F1C14C8AAD5EAF27746B"
      cert_valid_from     = "2024-07-12"
      cert_valid_to       = "2025-07-12"

      country             = "CA"
      state               = "Ontario"
      locality            = "Ottawa"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "57:b8:00:04:86:9f:a0:05:ea:8d:29:49:06:b0:a3:7e"
      )
}
