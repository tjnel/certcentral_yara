import "pe"

rule MAL_Compromised_Cert_CoinLurker_SSL_com_3CCAA910608E55352E5340C47D01A9D8 {
   meta:
      description         = "Detects CoinLurker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-14"
      version             = "1.0"

      hash                = "c8adb9bf6997a9fa2738a09600a60abc4fb6334aa54b24166cf042afdc5a1064"
      malware             = "CoinLurker"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Domum - design s.r.o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "3c:ca:a9:10:60:8e:55:35:2e:53:40:c4:7d:01:a9:d8"
      cert_thumbprint     = "78383AD96F00C6843126052D391DF597400925EA"
      cert_valid_from     = "2024-09-14"
      cert_valid_to       = "2025-09-14"

      country             = "CZ"
      state               = "Hlavní Mesto Praha"
      locality            = "Žižkov"
      email               = "???"
      rdn_serial_number   = "075 35 465"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "3c:ca:a9:10:60:8e:55:35:2e:53:40:c4:7d:01:a9:d8"
      )
}
