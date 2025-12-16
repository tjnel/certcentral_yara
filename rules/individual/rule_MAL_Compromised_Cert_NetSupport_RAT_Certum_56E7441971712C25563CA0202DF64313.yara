import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_Certum_56E7441971712C25563CA0202DF64313 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-06"
      version             = "1.0"

      hash                = "7f6bd2fb62b7d513213a4ea7e6da2750506600c60c1b42b32c75502906d428e4"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Guangxi Hanhe Information Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "56:e7:44:19:71:71:2c:25:56:3c:a0:20:2d:f6:43:13"
      cert_thumbprint     = "DCA3C823A7E4E4591DE17640A96803F6E496A3FF"
      cert_valid_from     = "2024-06-06"
      cert_valid_to       = "2025-06-06"

      country             = "CN"
      state               = "Guangxi-Zhuang Autonomous Region"
      locality            = "Nanning"
      email               = "???"
      rdn_serial_number   = "91450103MA5LBQKB3C"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "56:e7:44:19:71:71:2c:25:56:3c:a0:20:2d:f6:43:13"
      )
}
