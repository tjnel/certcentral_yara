import "pe"

rule MAL_Compromised_Cert_Beacon_Sectigo_5FD4677799C3297F39644688F9C12D31 {
   meta:
      description         = "Detects Beacon with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-09"
      version             = "1.0"

      hash                = "213188477c61f499705b55ab01b4b3c9536cbd92d20215d73837ae28bd129a94"
      malware             = "Beacon"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hefei Nudan Jukuang Network Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "5f:d4:67:77:99:c3:29:7f:39:64:46:88:f9:c1:2d:31"
      cert_thumbprint     = "A8BF7554363D27DEB374C4E2658AC05C60E3BAA7"
      cert_valid_from     = "2025-09-09"
      cert_valid_to       = "2026-09-09"

      country             = "CN"
      state               = "Anhui Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "5f:d4:67:77:99:c3:29:7f:39:64:46:88:f9:c1:2d:31"
      )
}
