import "pe"

rule MAL_Compromised_Cert_Crazy_Evil_Traffer_Team_SSL_com_56F6A688C743831312A4A80A6899DA37 {
   meta:
      description         = "Detects Crazy Evil Traffer Team with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-30"
      version             = "1.0"

      hash                = "ad89d781f68ee9b76c6ec279611e27317d45815b4f93fe496f136e9f40b4dc0b"
      malware             = "Crazy Evil Traffer Team"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "Love IT Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "56:f6:a6:88:c7:43:83:13:12:a4:a8:0a:68:99:da:37"
      cert_thumbprint     = "04D6C33D56249BBC30CFCA153AA719793B227148"
      cert_valid_from     = "2025-04-30"
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
         sig.serial == "56:f6:a6:88:c7:43:83:13:12:a4:a8:0a:68:99:da:37"
      )
}
