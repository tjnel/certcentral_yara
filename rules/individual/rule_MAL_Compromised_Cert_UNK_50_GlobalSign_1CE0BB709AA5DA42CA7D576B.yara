import "pe"

rule MAL_Compromised_Cert_UNK_50_GlobalSign_1CE0BB709AA5DA42CA7D576B {
   meta:
      description         = "Detects UNK-50 with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-14"
      version             = "1.0"

      hash                = "cc7e8f6e02d796a8f7bc2bb8dc8d96dfb0debb478d1adf40959a1870be36e6c7"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CENTRUM LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "1c:e0:bb:70:9a:a5:da:42:ca:7d:57:6b"
      cert_thumbprint     = "066265F1A9CBF90F507B61A216AD945E314717D7"
      cert_valid_from     = "2025-04-14"
      cert_valid_to       = "2026-04-15"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1237700505240"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "1c:e0:bb:70:9a:a5:da:42:ca:7d:57:6b"
      )
}
