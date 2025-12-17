import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_43098196E3855161C52769A0FEEFDBAC {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-09-18"
      version             = "1.0"

      hash                = "96c4b76ad445db36e273d4bfa23b3e9cb1a30db836d0b0c940d6f8c41b9d81c5"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Fodere Titanium Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "43:09:81:96:e3:85:51:61:c5:27:69:a0:fe:ef:db:ac"
      cert_thumbprint     = "16AFD0940C8FC1A3E0367CAFDFDEADE273AF46D4"
      cert_valid_from     = "2023-09-18"
      cert_valid_to       = "2024-09-17"

      country             = "GB"
      state               = "England"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "43:09:81:96:e3:85:51:61:c5:27:69:a0:fe:ef:db:ac"
      )
}
