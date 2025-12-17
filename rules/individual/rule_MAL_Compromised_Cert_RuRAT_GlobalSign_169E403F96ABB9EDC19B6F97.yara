import "pe"

rule MAL_Compromised_Cert_RuRAT_GlobalSign_169E403F96ABB9EDC19B6F97 {
   meta:
      description         = "Detects RuRAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-16"
      version             = "1.0"

      hash                = "18f25ebdcacc82ab01f4d53151cd575ec1f21cfd2eda5539eb1af9a9dec139ba"
      malware             = "RuRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Netzsh Scientific Instruments TRADING(Shanghai) Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "16:9e:40:3f:96:ab:b9:ed:c1:9b:6f:97"
      cert_thumbprint     = "DCB505B5FDFA36CC1EC4F6E15EAB6B9DA5C6B2B8"
      cert_valid_from     = "2024-08-16"
      cert_valid_to       = "2025-08-17"

      country             = "CN"
      state               = "Shanghai"
      locality            = "Shanghai"
      email               = "???"
      rdn_serial_number   = "9131011579706617XN"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "16:9e:40:3f:96:ab:b9:ed:c1:9b:6f:97"
      )
}
