import "pe"

rule MAL_Compromised_Cert_KorPlug_GlobalSign_06FA9DF25D522FB355CC41E8 {
   meta:
      description         = "Detects KorPlug with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-07"
      version             = "1.0"

      hash                = "2cd4fb94268ba063b1a5eea7fe87e794fecf46c0f56c2aaa81e8c9052bb4f5f2"
      malware             = "KorPlug"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xuaony Plantain E-Commerce Trading Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "06:fa:9d:f2:5d:52:2f:b3:55:cc:41:e8"
      cert_thumbprint     = "DFCDB964C7C596DBA245A066F08989C9AC1AD4B0"
      cert_valid_from     = "2024-04-07"
      cert_valid_to       = "2025-03-30"

      country             = "CN"
      state               = "Hubei"
      locality            = "Xiangyang"
      email               = "???"
      rdn_serial_number   = "91420600MACLU7R889"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "06:fa:9d:f2:5d:52:2f:b3:55:cc:41:e8"
      )
}
