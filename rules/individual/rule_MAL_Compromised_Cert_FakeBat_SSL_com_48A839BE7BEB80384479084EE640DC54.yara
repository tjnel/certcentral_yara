import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_48A839BE7BEB80384479084EE640DC54 {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-13"
      version             = "1.0"

      hash                = "42836bce8422d4faa74f52ff3515c73996a7b8f635d8848242988be677e2c556"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Canis Software Inc."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "48:a8:39:be:7b:eb:80:38:44:79:08:4e:e6:40:dc:54"
      cert_thumbprint     = "44B038A4EFD755EF6B88832D19DFAB2BBBD9237B"
      cert_valid_from     = "2024-05-13"
      cert_valid_to       = "2025-05-13"

      country             = "CA"
      state               = "Ontario"
      locality            = "Oakville"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "48:a8:39:be:7b:eb:80:38:44:79:08:4e:e6:40:dc:54"
      )
}
