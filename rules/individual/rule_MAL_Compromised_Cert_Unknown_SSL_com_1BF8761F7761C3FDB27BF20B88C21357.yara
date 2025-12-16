import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_1BF8761F7761C3FDB27BF20B88C21357 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-29"
      version             = "1.0"

      hash                = "97b9db9756c042500ce1947ead32734630fa3df4659ebebd07b549d7ca5c8b75"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "KEMROSE ENTERPRISES LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "1b:f8:76:1f:77:61:c3:fd:b2:7b:f2:0b:88:c2:13:57"
      cert_thumbprint     = "E1AA448D29371254654C29C65A5309686ACD93D0"
      cert_valid_from     = "2024-08-29"
      cert_valid_to       = "2025-08-28"

      country             = "KE"
      state               = "Nairobi"
      locality            = "Nairobi"
      email               = "???"
      rdn_serial_number   = "CPR/2010/34857"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "1b:f8:76:1f:77:61:c3:fd:b2:7b:f2:0b:88:c2:13:57"
      )
}
