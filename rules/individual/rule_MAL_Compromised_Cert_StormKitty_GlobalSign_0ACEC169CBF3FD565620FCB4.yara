import "pe"

rule MAL_Compromised_Cert_StormKitty_GlobalSign_0ACEC169CBF3FD565620FCB4 {
   meta:
      description         = "Detects StormKitty with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-19"
      version             = "1.0"

      hash                = "f84f4785d00356bf51a3ca9643dbbe3f778e9032fa365511732b5f4b9838e0a1"
      malware             = "StormKitty"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hefei Zaxue Network Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "0a:ce:c1:69:cb:f3:fd:56:56:20:fc:b4"
      cert_thumbprint     = "B670D67D1A8CCDDDB1BA518718DCA85074832D40"
      cert_valid_from     = "2025-05-19"
      cert_valid_to       = "2026-05-20"

      country             = "CN"
      state               = "Anhui"
      locality            = "Hefei"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "0a:ce:c1:69:cb:f3:fd:56:56:20:fc:b4"
      )
}
