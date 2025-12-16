import "pe"

rule MAL_Compromised_Cert_Bumblebee_GlobalSign_5C37013893858BA3EFBBED44 {
   meta:
      description         = "Detects Bumblebee with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-26"
      version             = "1.0"

      hash                = "29e1bc115d78c7e98e6dbc3577d24a75effda6d25f191cf32503f65922e3c281"
      malware             = "Bumblebee"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Vector"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5c:37:01:38:93:85:8b:a3:ef:bb:ed:44"
      cert_thumbprint     = "AADEFBD3722D85713F2F0233EFE25462D3D490AB"
      cert_valid_from     = "2025-05-26"
      cert_valid_to       = "2026-05-27"

      country             = "RU"
      state               = "Lipetsk Oblast"
      locality            = "Lipetsk"
      email               = "???"
      rdn_serial_number   = "1204800012317"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5c:37:01:38:93:85:8b:a3:ef:bb:ed:44"
      )
}
