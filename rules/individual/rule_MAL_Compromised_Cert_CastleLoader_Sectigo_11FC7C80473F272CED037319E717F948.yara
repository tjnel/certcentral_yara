import "pe"

rule MAL_Compromised_Cert_CastleLoader_Sectigo_11FC7C80473F272CED037319E717F948 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-13"
      version             = "1.0"

      hash                = "876a04d0f76dc14f68248e0b4498e3b710740e1447bcc6be6fd746b9c01276de"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Chengdu Yizhifeng Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "11:fc:7c:80:47:3f:27:2c:ed:03:73:19:e7:17:f9:48"
      cert_thumbprint     = "42ECD23FBCD5CCEC5D6E914B5B5653C9D267EE3C"
      cert_valid_from     = "2025-10-13"
      cert_valid_to       = "2026-10-13"

      country             = "CN"
      state               = "Sichuan Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91510100MABP1B9J8N"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "11:fc:7c:80:47:3f:27:2c:ed:03:73:19:e7:17:f9:48"
      )
}
