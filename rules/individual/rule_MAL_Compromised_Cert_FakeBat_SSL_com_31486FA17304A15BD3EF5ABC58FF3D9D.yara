import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_31486FA17304A15BD3EF5ABC58FF3D9D {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-09-21"
      version             = "1.0"

      hash                = "9ed7717cfd1d386e9179d259246e82914406c4481cb116fc24d3c22d5fc0a161"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Survi Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "31:48:6f:a1:73:04:a1:5b:d3:ef:5a:bc:58:ff:3d:9d"
      cert_thumbprint     = "30194B95D2E4F240B40AFD57F7A5AC2EB8DC11EF"
      cert_valid_from     = "2023-09-21"
      cert_valid_to       = "2024-09-20"

      country             = "GB"
      state               = "???"
      locality            = "Newcastle"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "31:48:6f:a1:73:04:a1:5b:d3:ef:5a:bc:58:ff:3d:9d"
      )
}
