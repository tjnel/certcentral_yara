import "pe"

rule MAL_Compromised_Cert_Rusty_Traffer_SSL_com_23A573F885C71A52D7A6E3217596CDF9 {
   meta:
      description         = "Detects Rusty Traffer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-06"
      version             = "1.0"

      hash                = "e8335db8f6d238699304e5d50e5499c84316bf25aaec46ec04be7a7b2bcd6cba"
      malware             = "Rusty Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Brys Software Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "23:a5:73:f8:85:c7:1a:52:d7:a6:e3:21:75:96:cd:f9"
      cert_thumbprint     = "F1E4B850544670D058ADA7A668A614D27B548BF7"
      cert_valid_from     = "2024-09-06"
      cert_valid_to       = "2025-09-06"

      country             = "GB"
      state               = "England"
      locality            = "Gateshead"
      email               = "???"
      rdn_serial_number   = "09335379"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "23:a5:73:f8:85:c7:1a:52:d7:a6:e3:21:75:96:cd:f9"
      )
}
