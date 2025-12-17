import "pe"

rule MAL_Compromised_Cert_SecTopRAT_ArechClient2_GlobalSign_27356F6B781B07D6F52FF68F {
   meta:
      description         = "Detects SecTopRAT,ArechClient2 with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-05"
      version             = "1.0"

      hash                = "4c3f5a22c67195cf75cc79b4351cca3ae91a56e39769874ef22f11fc61834dfd"
      malware             = "SecTopRAT,ArechClient2"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "MANH THAO NGUYEN COMPANY LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "27:35:6f:6b:78:1b:07:d6:f5:2f:f6:8f"
      cert_thumbprint     = "34fcec32f1579ad142b2f456c1c4e13dad9ffd2016500fe9e510c14d3bf50de7"
      cert_valid_from     = "2024-12-05"
      cert_valid_to       = "2025-12-06"

      country             = "VN"
      state               = "Ha Nam"
      locality            = "Ha Nam"
      email               = "EleonoraLipseyetu32@gmail.com"
      rdn_serial_number   = "0700863851"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "27:35:6f:6b:78:1b:07:d6:f5:2f:f6:8f"
      )
}
