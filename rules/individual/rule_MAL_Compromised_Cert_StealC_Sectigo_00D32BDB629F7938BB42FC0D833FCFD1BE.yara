import "pe"

rule MAL_Compromised_Cert_StealC_Sectigo_00D32BDB629F7938BB42FC0D833FCFD1BE {
   meta:
      description         = "Detects StealC with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-22"
      version             = "1.0"

      hash                = "a7b351abcc254df7750d69e327aabcf15bd458b229b0a43347cc1e374870d1bb"
      malware             = "StealC"
      malware_type        = "Infostealer"
      malware_notes       = ""

      signer              = "Taiyuan Yuqianhan Network Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:d3:2b:db:62:9f:79:38:bb:42:fc:0d:83:3f:cf:d1:be"
      cert_thumbprint     = "B5387C95C39382109179FFDAA557BE97C303BFFD"
      cert_valid_from     = "2025-08-22"
      cert_valid_to       = "2026-08-22"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:d3:2b:db:62:9f:79:38:bb:42:fc:0d:83:3f:cf:d1:be"
      )
}
