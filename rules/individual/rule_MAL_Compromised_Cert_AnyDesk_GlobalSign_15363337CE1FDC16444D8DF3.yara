import "pe"

rule MAL_Compromised_Cert_AnyDesk_GlobalSign_15363337CE1FDC16444D8DF3 {
   meta:
      description         = "Detects AnyDesk with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-30"
      version             = "1.0"

      hash                = "251101b834ae02e78bae30ab284567b513af6697c7e7ba824b3f9ebd93570dca"
      malware             = "AnyDesk"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MIKA LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "15:36:33:37:ce:1f:dc:16:44:4d:8d:f3"
      cert_thumbprint     = "59EAADA4C4F218ED6A0C32FA15D463A3638D972E"
      cert_valid_from     = "2024-12-30"
      cert_valid_to       = "2025-12-31"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1247700784583"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "15:36:33:37:ce:1f:dc:16:44:4d:8d:f3"
      )
}
