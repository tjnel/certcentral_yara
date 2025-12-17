import "pe"

rule MAL_Compromised_Cert_Crazy_Evil_Traffer_Team_SSL_com_65DC74FC2995EC9FE2D2E7A616CFE915 {
   meta:
      description         = "Detects Crazy Evil Traffer Team with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-12"
      version             = "1.0"

      hash                = "11c7f91ea98a308d0bedc982e2074b799ea83fdb09f3a8c4c7b5292eaeedae32"
      malware             = "Crazy Evil Traffer Team"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "It Go Pro SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "65:dc:74:fc:29:95:ec:9f:e2:d2:e7:a6:16:cf:e9:15"
      cert_thumbprint     = "58DD911EBB1DF8A945590523BEB60277CEC17517"
      cert_valid_from     = "2025-05-12"
      cert_valid_to       = "2026-05-12"

      country             = "PL"
      state               = "Województwo śląskie"
      locality            = "Katowice"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "65:dc:74:fc:29:95:ec:9f:e2:d2:e7:a6:16:cf:e9:15"
      )
}
