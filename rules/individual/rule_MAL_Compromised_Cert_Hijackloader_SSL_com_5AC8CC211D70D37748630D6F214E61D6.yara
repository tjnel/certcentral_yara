import "pe"

rule MAL_Compromised_Cert_Hijackloader_SSL_com_5AC8CC211D70D37748630D6F214E61D6 {
   meta:
      description         = "Detects Hijackloader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-07"
      version             = "1.0"

      hash                = "d7e5be8aa67b33d9cd681c126c5523c919692ef44af69b470def0863d2f28120"
      malware             = "Hijackloader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "KTNF Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "5a:c8:cc:21:1d:70:d3:77:48:63:0d:6f:21:4e:61:d6"
      cert_thumbprint     = "6193FB8FE7540E0C3BF341B76B0A834A83A03A57"
      cert_valid_from     = "2025-05-07"
      cert_valid_to       = "2026-05-07"

      country             = "KR"
      state               = "???"
      locality            = "Seoul"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "5a:c8:cc:21:1d:70:d3:77:48:63:0d:6f:21:4e:61:d6"
      )
}
