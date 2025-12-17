import "pe"

rule MAL_Compromised_Cert_BumbleBee_GlobalSign_1044DC08D7A1CEAD020B97EC {
   meta:
      description         = "Detects BumbleBee with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-14"
      version             = "1.0"

      hash                = "bd9767ccf80f530171bddbfccd73f25679d67a34e3290f230245270ea45f02d7"
      malware             = "BumbleBee"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Best Consult"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "10:44:dc:08:d7:a1:ce:ad:02:0b:97:ec"
      cert_thumbprint     = "5CD43E67385486F0022189B55D769BEE4AA5D8BF"
      cert_valid_from     = "2025-05-14"
      cert_valid_to       = "2026-05-15"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1167746280855"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "10:44:dc:08:d7:a1:ce:ad:02:0b:97:ec"
      )
}
