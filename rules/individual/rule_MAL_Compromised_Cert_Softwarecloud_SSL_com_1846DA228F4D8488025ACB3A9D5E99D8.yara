import "pe"

rule MAL_Compromised_Cert_Softwarecloud_SSL_com_1846DA228F4D8488025ACB3A9D5E99D8 {
   meta:
      description         = "Detects Softwarecloud with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-03"
      version             = "1.0"

      hash                = "662de27500ad4310febb0d2fa962fe902aa89d1f91215ddf0f694161faa4e174"
      malware             = "Softwarecloud"
      malware_type        = "Unknown"
      malware_notes       = "This malware is part of a campaign of inauthentic software. More research is likely needed: https://x.com/andrewdanis/status/1919585650413629680?s=20"

      signer              = "JUST CREATE SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "18:46:da:22:8f:4d:84:88:02:5a:cb:3a:9d:5e:99:d8"
      cert_thumbprint     = "E13C309ED10E0618FD6E7A510E5ECA9262C2B031"
      cert_valid_from     = "2025-06-03"
      cert_valid_to       = "2026-06-03"

      country             = "PL"
      state               = "Lower Silesian Voivodeship"
      locality            = "Wrocław"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "18:46:da:22:8f:4d:84:88:02:5a:cb:3a:9d:5e:99:d8"
      )
}
