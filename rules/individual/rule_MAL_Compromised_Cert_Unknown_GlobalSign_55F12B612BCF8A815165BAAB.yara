import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_55F12B612BCF8A815165BAAB {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-19"
      version             = "1.0"

      hash                = "c75936d5da7d2856cd5642211a4dde6bdeae598d77b935762162d4b493a621d5"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Yongji Xiaodong Network Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "55:f1:2b:61:2b:cf:8a:81:51:65:ba:ab"
      cert_thumbprint     = "DDB7EF4C785F05E6FCA4913CD4993BB757B6AD69"
      cert_valid_from     = "2025-05-19"
      cert_valid_to       = "2026-05-20"

      country             = "CN"
      state               = "Shanxi"
      locality            = "Yuncheng"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "55:f1:2b:61:2b:cf:8a:81:51:65:ba:ab"
      )
}
