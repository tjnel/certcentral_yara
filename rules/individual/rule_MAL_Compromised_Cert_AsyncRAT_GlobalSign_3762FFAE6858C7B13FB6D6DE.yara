import "pe"

rule MAL_Compromised_Cert_AsyncRAT_GlobalSign_3762FFAE6858C7B13FB6D6DE {
   meta:
      description         = "Detects AsyncRAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-25"
      version             = "1.0"

      hash                = "67c0645892b01e1f72ef11e706902a7f465f005fac695806ba686528439a184c"
      malware             = "AsyncRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "安徽星战信息科技有限公司"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "37:62:ff:ae:68:58:c7:b1:3f:b6:d6:de"
      cert_thumbprint     = "6E27FDB6AEFF50188702E3AEEA723D020F22F2C5"
      cert_valid_from     = "2024-11-25"
      cert_valid_to       = "2026-01-07"

      country             = "CN"
      state               = "安徽省"
      locality            = "芜湖市"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "37:62:ff:ae:68:58:c7:b1:3f:b6:d6:de"
      )
}
