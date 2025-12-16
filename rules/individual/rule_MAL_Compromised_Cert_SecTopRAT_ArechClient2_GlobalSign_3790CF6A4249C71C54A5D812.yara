import "pe"

rule MAL_Compromised_Cert_SecTopRAT_ArechClient2_GlobalSign_3790CF6A4249C71C54A5D812 {
   meta:
      description         = "Detects SecTopRAT,ArechClient2 with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-06"
      version             = "1.0"

      hash                = "d864a359e3a19182e72109fe75408d21b10215938e8be4098c4dbbc8ce0b7c7c"
      malware             = "SecTopRAT,ArechClient2"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Hebei Qianyuan Biopharmaceutical Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "37:90:cf:6a:42:49:c7:1c:54:a5:d8:12"
      cert_thumbprint     = "F2EA1DD98D1AF0F9044C24B266475A5C61C6A658"
      cert_valid_from     = "2024-06-06"
      cert_valid_to       = "2025-06-07"

      country             = "CN"
      state               = "Hebei"
      locality            = "Shijiazhuang"
      email               = "???"
      rdn_serial_number   = "91130123MA09YCKA2U"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "37:90:cf:6a:42:49:c7:1c:54:a5:d8:12"
      )
}
