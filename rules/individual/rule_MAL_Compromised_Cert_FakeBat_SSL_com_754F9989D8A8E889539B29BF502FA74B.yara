import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_754F9989D8A8E889539B29BF502FA74B {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-12-15"
      version             = "1.0"

      hash                = "ad6bcffb161cb9fb0eca2905ca8c4c0365aa4febab6f47acabcbf8b4b75d478c"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Consoneai Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "75:4f:99:89:d8:a8:e8:89:53:9b:29:bf:50:2f:a7:4b"
      cert_thumbprint     = "57AC3537F14B3059FA016FEAA5825FE72704AF2B"
      cert_valid_from     = "2023-12-15"
      cert_valid_to       = "2024-12-13"

      country             = "GB"
      state               = "England"
      locality            = "Wetherby"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "75:4f:99:89:d8:a8:e8:89:53:9b:29:bf:50:2f:a7:4b"
      )
}
