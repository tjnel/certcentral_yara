import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_6BDB08B7DDB773720764005D7E7DED8B {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-17"
      version             = "1.0"

      hash                = "5f9557f616ab8c007422a7bf034b75548c73d818fdac84f82ef48b7f26662de6"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Creative Ustawi Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "6b:db:08:b7:dd:b7:73:72:07:64:00:5d:7e:7d:ed:8b"
      cert_thumbprint     = "F65D1315C9B5DABF3BE1CE4F17F5D85E88484013"
      cert_valid_from     = "2024-05-17"
      cert_valid_to       = "2025-05-17"

      country             = "GB"
      state               = "England"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "6b:db:08:b7:dd:b7:73:72:07:64:00:5d:7e:7d:ed:8b"
      )
}
