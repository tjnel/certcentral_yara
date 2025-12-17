import "pe"

rule MAL_Compromised_Cert_FakePutty_Sectigo_00FD7B8FA580A5360A2D82E905D75915F8 {
   meta:
      description         = "Detects FakePutty with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-22"
      version             = "1.0"

      hash                = "0e1f3368fff264dc342d985981f8e15aac7f39b866aae21a74e868409ca720bc"
      malware             = "FakePutty"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Songyuan Shashu Network Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:fd:7b:8f:a5:80:a5:36:0a:2d:82:e9:05:d7:59:15:f8"
      cert_thumbprint     = "281A0F64D467B653DF2D46258E6E769B04629AE5"
      cert_valid_from     = "2025-07-22"
      cert_valid_to       = "2026-10-20"

      country             = "CN"
      state               = "Jilin Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91220702MABP4WUC8L"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:fd:7b:8f:a5:80:a5:36:0a:2d:82:e9:05:d7:59:15:f8"
      )
}
