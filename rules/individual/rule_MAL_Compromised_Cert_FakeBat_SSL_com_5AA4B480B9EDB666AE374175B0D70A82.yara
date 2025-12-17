import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_5AA4B480B9EDB666AE374175B0D70A82 {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-07"
      version             = "1.0"

      hash                = "ce33a8aabc0095ee679cb0cbf6e7fb69b50611abfa85533d1daa18d7dcadb2b5"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Fabled Creative Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "5a:a4:b4:80:b9:ed:b6:66:ae:37:41:75:b0:d7:0a:82"
      cert_thumbprint     = "6056787F07F92C123A775057A9F7EB9C8905E1EA"
      cert_valid_from     = "2024-05-07"
      cert_valid_to       = "2025-05-07"

      country             = "GB"
      state               = "Scotland"
      locality            = "Edinburgh"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "5a:a4:b4:80:b9:ed:b6:66:ae:37:41:75:b0:d7:0a:82"
      )
}
