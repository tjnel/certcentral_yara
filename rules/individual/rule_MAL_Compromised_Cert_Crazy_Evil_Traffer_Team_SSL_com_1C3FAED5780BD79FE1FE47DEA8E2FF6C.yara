import "pe"

rule MAL_Compromised_Cert_Crazy_Evil_Traffer_Team_SSL_com_1C3FAED5780BD79FE1FE47DEA8E2FF6C {
   meta:
      description         = "Detects Crazy Evil Traffer Team with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-18"
      version             = "1.0"

      hash                = "67d9a42df044f1bec25fa3fd0f69ea6ba675c9289ff4a7e16c9fa470f1f69257"
      malware             = "Crazy Evil Traffer Team"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "Love IT Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "1c:3f:ae:d5:78:0b:d7:9f:e1:fe:47:de:a8:e2:ff:6c"
      cert_thumbprint     = "52468B310485AC58CFE6CD717F409314884C0EF7"
      cert_valid_from     = "2025-04-18"
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
         sig.serial == "1c:3f:ae:d5:78:0b:d7:9f:e1:fe:47:de:a8:e2:ff:6c"
      )
}
