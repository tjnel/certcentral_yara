import "pe"

rule MAL_Compromised_Cert_SecTopRAT_ArechClient2_GlobalSign_3B17B73A15A48A30DD2EDC71 {
   meta:
      description         = "Detects SecTopRAT,ArechClient2 with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-06"
      version             = "1.0"

      hash                = "bcff246f0739ed98f8aa615d256e7e00bc1cb24c8cabaea609b25c3f050c7805"
      malware             = "SecTopRAT,ArechClient2"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Brave Pragmatic Network Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3b:17:b7:3a:15:a4:8a:30:dd:2e:dc:71"
      cert_thumbprint     = "4BDBF5954EDE0FF642960B7A8601D962F6B3D8CD"
      cert_valid_from     = "2024-08-06"
      cert_valid_to       = "2025-08-07"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Guangzhou"
      email               = "???"
      rdn_serial_number   = "91440101MA9URAWW0Q"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3b:17:b7:3a:15:a4:8a:30:dd:2e:dc:71"
      )
}
