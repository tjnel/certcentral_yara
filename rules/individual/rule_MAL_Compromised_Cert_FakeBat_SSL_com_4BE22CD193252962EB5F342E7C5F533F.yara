import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_4BE22CD193252962EB5F342E7C5F533F {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-12-20"
      version             = "1.0"

      hash                = "bbc1dd5ce5d7079b77927b72918810e5effe54cdeab042c848b0b20624119f75"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Pehotav Engineering Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "4b:e2:2c:d1:93:25:29:62:eb:5f:34:2e:7c:5f:53:3f"
      cert_thumbprint     = "124C66197CBC4DE925E6CC86240F0CD3B74D2F4D"
      cert_valid_from     = "2023-12-20"
      cert_valid_to       = "2024-12-19"

      country             = "GB"
      state               = "???"
      locality            = "Harrow"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "4b:e2:2c:d1:93:25:29:62:eb:5f:34:2e:7c:5f:53:3f"
      )
}
