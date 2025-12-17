import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_130E3B9CA29F3AB9F3EB6C78CEE34E7C {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-08"
      version             = "1.0"

      hash                = "b3c3cdd9e888ab607b9e146cf83cdca6b9810c2350c95ecea6b2990b9aba955a"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Gma Technology Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "13:0e:3b:9c:a2:9f:3a:b9:f3:eb:6c:78:ce:e3:4e:7c"
      cert_thumbprint     = "B5552BF22175AF5D4E9E54B5086B89E8913DB7B9"
      cert_valid_from     = "2024-08-08"
      cert_valid_to       = "2025-08-08"

      country             = "GB"
      state               = "England"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "09959900"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "13:0e:3b:9c:a2:9f:3a:b9:f3:eb:6c:78:ce:e3:4e:7c"
      )
}
