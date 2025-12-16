import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_594ADDB2E19E4393A541C5F6 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-08"
      version             = "1.0"

      hash                = "9d1379a5f6efdf1ce131cda5fe91fd52de836479f5bdebee3100c2bbd64bd8b2"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "武汉市芙樾琳网络科技有限公司"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "59:4a:dd:b2:e1:9e:43:93:a5:41:c5:f6"
      cert_thumbprint     = "4BF0413657EFBA125F18AF180A5D2A47E47B07E5"
      cert_valid_from     = "2025-04-08"
      cert_valid_to       = "2026-04-09"

      country             = "CN"
      state               = "湖北省"
      locality            = "武汉市"
      email               = "???"
      rdn_serial_number   = "91420116MAEEPPAC1G"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "59:4a:dd:b2:e1:9e:43:93:a5:41:c5:f6"
      )
}
