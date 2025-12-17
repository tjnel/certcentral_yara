import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_22D2367F46F93A3893E608768BB8F79A {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-17"
      version             = "1.0"

      hash                = "5663eb21e88082bedc1545e21cdb25ad17b44bdeca5ca28c359b191d048efc94"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Bealearts Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "22:d2:36:7f:46:f9:3a:38:93:e6:08:76:8b:b8:f7:9a"
      cert_thumbprint     = "5F2F1060CBB416F8DAEA275A2DBB6A8C6877C6F0"
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
         sig.serial == "22:d2:36:7f:46:f9:3a:38:93:e6:08:76:8b:b8:f7:9a"
      )
}
