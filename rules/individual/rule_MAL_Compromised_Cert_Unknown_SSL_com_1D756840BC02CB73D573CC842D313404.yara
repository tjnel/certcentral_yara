import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_1D756840BC02CB73D573CC842D313404 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-14"
      version             = "1.0"

      hash                = "87c505ec04c3766bd881d6eb0c3a9f07106513d62ea7d0256b3927cf51e405f8"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "DEVELOPMENT ASCENT LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "1d:75:68:40:bc:02:cb:73:d5:73:cc:84:2d:31:34:04"
      cert_thumbprint     = "FDF4C1281360424CA15B2F3DA4E63D7C4A722A62"
      cert_valid_from     = "2024-11-14"
      cert_valid_to       = "2025-11-14"

      country             = "GB"
      state               = "???"
      locality            = "Edinburgh"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "1d:75:68:40:bc:02:cb:73:d5:73:cc:84:2d:31:34:04"
      )
}
