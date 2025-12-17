import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_7BC5EBCE60E231C20CE56703FE461C0C {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-12-20"
      version             = "1.0"

      hash                = "5d84ec3475fac25a1691b3bc831737b5b3d02454613ccb492de4972432494cf5"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Nja Engineering Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "7b:c5:eb:ce:60:e2:31:c2:0c:e5:67:03:fe:46:1c:0c"
      cert_thumbprint     = "1B2B17BADBFE11858FD56243105EC9429724B6F6"
      cert_valid_from     = "2023-12-20"
      cert_valid_to       = "2024-12-19"

      country             = "GB"
      state               = "???"
      locality            = "Stockport"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "7b:c5:eb:ce:60:e2:31:c2:0c:e5:67:03:fe:46:1c:0c"
      )
}
