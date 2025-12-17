import "pe"

rule MAL_Compromised_Cert_FakeDocusign_SSL_com_63B13BB7320117B3A722735ECB578BB5 {
   meta:
      description         = "Detects FakeDocusign with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-21"
      version             = "1.0"

      hash                = "10d664e9f7eca0bf6c9c58b81d0c564256ef90b09a8d02549b3342b598a7a6d1"
      malware             = "FakeDocusign"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Kuopio Trade Park Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "63:b1:3b:b7:32:01:17:b3:a7:22:73:5e:cb:57:8b:b5"
      cert_thumbprint     = "CE7B5DB515209591AE13FBED5881E2D0AA9F193F"
      cert_valid_from     = "2025-08-21"
      cert_valid_to       = "2026-08-21"

      country             = "FI"
      state               = "North Karelia"
      locality            = "Joensuu"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "63:b1:3b:b7:32:01:17:b3:a7:22:73:5e:cb:57:8b:b5"
      )
}
