import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_GlobalSign_7EA850C5676DE6B09C0C3FFC {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-18"
      version             = "1.0"

      hash                = "73ce9b07e5cf79583ee18bd1472569a2edb609cf361f5ddb38b1b839056e94d9"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "EzDistract MicroLeague Network Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7e:a8:50:c5:67:6d:e6:b0:9c:0c:3f:fc"
      cert_thumbprint     = "94E8ECDF676564945E0CC02F5D7B54A6567458C7"
      cert_valid_from     = "2024-10-18"
      cert_valid_to       = "2025-10-19"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Chengdu"
      email               = "???"
      rdn_serial_number   = "91510100MA6B62U07Y"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7e:a8:50:c5:67:6d:e6:b0:9c:0c:3f:fc"
      )
}
