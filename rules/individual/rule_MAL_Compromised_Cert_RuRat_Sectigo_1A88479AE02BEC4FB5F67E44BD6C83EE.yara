import "pe"

rule MAL_Compromised_Cert_RuRat_Sectigo_1A88479AE02BEC4FB5F67E44BD6C83EE {
   meta:
      description         = "Detects RuRat with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-12"
      version             = "1.0"

      hash                = "7fc48dccd7c60e6779dd63e4ed31672d9a9d664fd46849fa1086bede630293e8"
      malware             = "RuRat"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Jiangyin furniture-homewares Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "1a:88:47:9a:e0:2b:ec:4f:b5:f6:7e:44:bd:6c:83:ee"
      cert_thumbprint     = ""
      cert_valid_from     = "2026-01-12"
      cert_valid_to       = "2027-01-12"

      country             = "CN"
      state               = "Jiangsu Sheng"
      locality            = "???"
      email               = ""
      rdn_serial_number   = "91320281MA20B1986E"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "1a:88:47:9a:e0:2b:ec:4f:b5:f6:7e:44:bd:6c:83:ee"
      )
}
