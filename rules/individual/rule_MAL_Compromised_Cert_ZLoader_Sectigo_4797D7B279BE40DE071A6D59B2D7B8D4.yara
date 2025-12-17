import "pe"

rule MAL_Compromised_Cert_ZLoader_Sectigo_4797D7B279BE40DE071A6D59B2D7B8D4 {
   meta:
      description         = "Detects ZLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-10-09"
      version             = "1.0"

      hash                = "78c6567201eeeaa1a359ab8929325de30abf18c22993de371a08b7c9bc0af04c"
      malware             = "ZLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "NALA LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "47:97:d7:b2:79:be:40:de:07:1a:6d:59:b2:d7:b8:d4"
      cert_thumbprint     = "293B74A66F8F54B1EB4D9EE5EAE0D06F3B5EFD80"
      cert_valid_from     = "2020-10-09"
      cert_valid_to       = "2021-10-09"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "47:97:d7:b2:79:be:40:de:07:1a:6d:59:b2:d7:b8:d4"
      )
}
