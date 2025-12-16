import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_383BB880E7ACBA2928D2CBC6AB7BBE5C {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-03"
      version             = "1.0"

      hash                = "900cc09fcdd78ee16eacc91459abf31c088dc0434907390c7329469129dc917e"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Galbreath Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "38:3b:b8:80:e7:ac:ba:29:28:d2:cb:c6:ab:7b:be:5c"
      cert_thumbprint     = "B00982260BAABDBA964EA131411684DDF43DEB1C"
      cert_valid_from     = "2024-05-03"
      cert_valid_to       = "2025-05-03"

      country             = "GB"
      state               = "Scotland"
      locality            = "Linlithgow"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "38:3b:b8:80:e7:ac:ba:29:28:d2:cb:c6:ab:7b:be:5c"
      )
}
