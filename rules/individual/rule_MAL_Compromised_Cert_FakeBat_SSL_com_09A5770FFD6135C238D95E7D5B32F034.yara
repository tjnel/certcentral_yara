import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_09A5770FFD6135C238D95E7D5B32F034 {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-17"
      version             = "1.0"

      hash                = "8dc74a08a67d2dd84f2c676b14cc2c6e83f97b87e2a668d9cc3321f7b9a29601"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Apogee Creative Inc."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "09:a5:77:0f:fd:61:35:c2:38:d9:5e:7d:5b:32:f0:34"
      cert_thumbprint     = "2AE6EC4FE575314C176D15B29CBE50DD946D3E9F"
      cert_valid_from     = "2024-05-17"
      cert_valid_to       = "2025-05-17"

      country             = "CA"
      state               = "Ontario"
      locality            = "Ottawa"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "09:a5:77:0f:fd:61:35:c2:38:d9:5e:7d:5b:32:f0:34"
      )
}
