import "pe"

rule MAL_Compromised_Cert_CryptoWalletChromeExtension_GlobalSign_382D0BDD4B9AB0C19F034D2C {
   meta:
      description         = "Detects CryptoWalletChromeExtension with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-13"
      version             = "1.0"

      hash                = "7a019835c112d203329039c22db86f1c6c355fdacad6e7d7525e6f475dcd0d70"
      malware             = "CryptoWalletChromeExtension"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "OLAN LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "38:2d:0b:dd:4b:9a:b0:c1:9f:03:4d:2c"
      cert_thumbprint     = "89023183222F27A7A8D65164ED63E53ABD32E68B"
      cert_valid_from     = "2025-08-13"
      cert_valid_to       = "2026-06-24"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "38:2d:0b:dd:4b:9a:b0:c1:9f:03:4d:2c"
      )
}
