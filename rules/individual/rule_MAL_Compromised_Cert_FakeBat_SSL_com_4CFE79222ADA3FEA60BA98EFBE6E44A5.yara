import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_4CFE79222ADA3FEA60BA98EFBE6E44A5 {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-03"
      version             = "1.0"

      hash                = "0c2997d95062a86ef9845f7bfd595d476e578db07def8e89ae26614c78a4e025"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Forth View Designs Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "4c:fe:79:22:2a:da:3f:ea:60:ba:98:ef:be:6e:44:a5"
      cert_thumbprint     = "A5540F1A24B23406A5B7B98357FFEFCB3B269F44"
      cert_valid_from     = "2024-05-03"
      cert_valid_to       = "2025-05-03"

      country             = "GB"
      state               = "Scotland"
      locality            = "Glasgow"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "4c:fe:79:22:2a:da:3f:ea:60:ba:98:ef:be:6e:44:a5"
      )
}
