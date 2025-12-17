import "pe"

rule MAL_Compromised_Cert_Softwarecloud_SSL_com_4F0659FE1BF2E22EDEC456C9794BF440 {
   meta:
      description         = "Detects Softwarecloud with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-27"
      version             = "1.0"

      hash                = "f80ab5dd208678cbd0c9b1da522fa179cb67cad263ea69e878a62fa97478fcb1"
      malware             = "Softwarecloud"
      malware_type        = "Unknown"
      malware_notes       = "This malware is part of a campaign of inauthentic software. More research is likely needed: https://x.com/andrewdanis/status/1919585650413629680?s=20"

      signer              = "Chip It Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "4f:06:59:fe:1b:f2:e2:2e:de:c4:56:c9:79:4b:f4:40"
      cert_thumbprint     = "017DA1710A71ABF8BA0620F3058CDD745771F4F2"
      cert_valid_from     = "2025-06-27"
      cert_valid_to       = "2026-06-27"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Espoo"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "4f:06:59:fe:1b:f2:e2:2e:de:c4:56:c9:79:4b:f4:40"
      )
}
