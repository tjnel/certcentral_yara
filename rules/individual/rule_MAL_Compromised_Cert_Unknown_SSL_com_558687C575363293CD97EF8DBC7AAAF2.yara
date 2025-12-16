import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_558687C575363293CD97EF8DBC7AAAF2 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-04"
      version             = "1.0"

      hash                = "ec0249a82e80a8856f4d50b537075f67f88a392ce20bb5fbaa18f0f069d91cd9"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Yuval Ben Itzhak"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "55:86:87:c5:75:36:32:93:cd:97:ef:8d:bc:7a:aa:f2"
      cert_thumbprint     = "61d45d0d0dcdb9a585260f036664d41e702ef3c2f4ec6ef6a86217a9a329d30b"
      cert_valid_from     = "2025-09-04"
      cert_valid_to       = "2026-09-03"

      country             = "CZ"
      state               = "Praha, Hlavní město"
      locality            = "Prague"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "55:86:87:c5:75:36:32:93:cd:97:ef:8d:bc:7a:aa:f2"
      )
}
