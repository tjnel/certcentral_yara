import "pe"

rule MAL_Compromised_Cert_Rusty_Traffer_SSL_com_53ABAB13428612102D8F6C07F39BBE53 {
   meta:
      description         = "Detects Rusty Traffer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-27"
      version             = "1.0"

      hash                = "b11005923c12dcb5e7f5a84ca99891a4c7e5b4c9080c5de14ffc6c6a42c4fafd"
      malware             = "Rusty Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Finish IT OY"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "53:ab:ab:13:42:86:12:10:2d:8f:6c:07:f3:9b:be:53"
      cert_thumbprint     = "FDB5194E127D5EEBF64E74CE92317B87A31259BE"
      cert_valid_from     = "2025-03-27"
      cert_valid_to       = "2026-03-27"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Espoo"
      email               = "???"
      rdn_serial_number   = "3086529-1"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "53:ab:ab:13:42:86:12:10:2d:8f:6c:07:f3:9b:be:53"
      )
}
