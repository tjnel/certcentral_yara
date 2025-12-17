import "pe"

rule MAL_Compromised_Cert_FakeBat_Certificate_SSL_com_03FC0BBCD0A7F34E9FD5A4DBCCF9C7F5 {
   meta:
      description         = "Detects FakeBat_Certificate with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-30"
      version             = "1.0"

      hash                = "43cc21310beb59713919f022c2e04bb3818de06f069afc24abad47424d1c0b85"
      malware             = "FakeBat_Certificate"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "RRVN Soft Technologies Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "03:fc:0b:bc:d0:a7:f3:4e:9f:d5:a4:db:cc:f9:c7:f5"
      cert_thumbprint     = "B4F05F1D350989E65666340113F7001C94BD11E9"
      cert_valid_from     = "2024-05-30"
      cert_valid_to       = "2025-05-30"

      country             = "GB"
      state               = "England"
      locality            = "Ilford"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "03:fc:0b:bc:d0:a7:f3:4e:9f:d5:a4:db:cc:f9:c7:f5"
      )
}
