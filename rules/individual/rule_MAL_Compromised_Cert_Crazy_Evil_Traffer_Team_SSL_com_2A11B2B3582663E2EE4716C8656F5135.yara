import "pe"

rule MAL_Compromised_Cert_Crazy_Evil_Traffer_Team_SSL_com_2A11B2B3582663E2EE4716C8656F5135 {
   meta:
      description         = "Detects Crazy Evil Traffer Team with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-28"
      version             = "1.0"

      hash                = "ffb7bb2d46fc715cb14689b618389c818452901372e79edd905d534c9a4f6a32"
      malware             = "Crazy Evil Traffer Team"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "Love IT Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "2a:11:b2:b3:58:26:63:e2:ee:47:16:c8:65:6f:51:35"
      cert_thumbprint     = "51B029D29CCAF3441CD99FE074743E8A2FA4EB77"
      cert_valid_from     = "2025-04-28"
      cert_valid_to       = "2026-04-18"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Vantaa"
      email               = "???"
      rdn_serial_number   = "2960500-3"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "2a:11:b2:b3:58:26:63:e2:ee:47:16:c8:65:6f:51:35"
      )
}
