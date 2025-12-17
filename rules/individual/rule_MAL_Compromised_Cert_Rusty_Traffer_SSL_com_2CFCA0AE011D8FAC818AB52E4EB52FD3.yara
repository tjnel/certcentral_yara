import "pe"

rule MAL_Compromised_Cert_Rusty_Traffer_SSL_com_2CFCA0AE011D8FAC818AB52E4EB52FD3 {
   meta:
      description         = "Detects Rusty Traffer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-09"
      version             = "1.0"

      hash                = "ad1e0acfc98d0e095abc1ab0c510042f51ea2e50974f517cb178612c2a456acd"
      malware             = "Rusty Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SOFT POWER SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "2c:fc:a0:ae:01:1d:8f:ac:81:8a:b5:2e:4e:b5:2f:d3"
      cert_thumbprint     = "FE9704017678BD4F30A707A3AED4ED9D30410C45"
      cert_valid_from     = "2025-05-09"
      cert_valid_to       = "2026-05-09"

      country             = "PL"
      state               = "dolnośląskie"
      locality            = "Wrocław"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "2c:fc:a0:ae:01:1d:8f:ac:81:8a:b5:2e:4e:b5:2f:d3"
      )
}
