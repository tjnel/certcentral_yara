import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_7A562978D709B11CAC4D6FCBA14954DB {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-10"
      version             = "1.0"

      hash                = "a83dd6a6ae07843b72caf4552474ec703c13050e61ba8e78ba0a72721a0d099b"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Paul Garner Consulting Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "7a:56:29:78:d7:09:b1:1c:ac:4d:6f:cb:a1:49:54:db"
      cert_thumbprint     = "E019D7719F55161534BB0C37DFFEFF1EF564AC31"
      cert_valid_from     = "2024-09-10"
      cert_valid_to       = "2025-09-10"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "09714891"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "7a:56:29:78:d7:09:b1:1c:ac:4d:6f:cb:a1:49:54:db"
      )
}
