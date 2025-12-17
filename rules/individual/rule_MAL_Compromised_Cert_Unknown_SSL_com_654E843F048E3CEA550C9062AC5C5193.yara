import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_654E843F048E3CEA550C9062AC5C5193 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-01"
      version             = "1.0"

      hash                = "f82bee604ef597b2dcd0d8f5871680fe1233c70867214ec78f050388f3b02691"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Paperbucketmdb ApS"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "65:4e:84:3f:04:8e:3c:ea:55:0c:90:62:ac:5c:51:93"
      cert_thumbprint     = "8456DDD90485387174852FCCE67241103F0E56F8"
      cert_valid_from     = "2025-04-01"
      cert_valid_to       = "2026-04-01"

      country             = "DK"
      state               = "Hovedstaden"
      locality            = "København"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "65:4e:84:3f:04:8e:3c:ea:55:0c:90:62:ac:5c:51:93"
      )
}
