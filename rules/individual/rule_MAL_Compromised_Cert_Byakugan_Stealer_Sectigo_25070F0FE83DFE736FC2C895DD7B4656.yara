import "pe"

rule MAL_Compromised_Cert_Byakugan_Stealer_Sectigo_25070F0FE83DFE736FC2C895DD7B4656 {
   meta:
      description         = "Detects Byakugan Stealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-05"
      version             = "1.0"

      hash                = "ef62ce2ae04a2e0cbb43b6dc20081e1b6129b6e5afe9f2fb036e62f97a1113ff"
      malware             = "Byakugan Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hefei Liutingdong Network Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "25:07:0f:0f:e8:3d:fe:73:6f:c2:c8:95:dd:7b:46:56"
      cert_thumbprint     = "3AEC77A9ED25D48AE368276EE691FB4424207930"
      cert_valid_from     = "2025-09-05"
      cert_valid_to       = "2026-09-05"

      country             = "CN"
      state               = "Anhui Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "25:07:0f:0f:e8:3d:fe:73:6f:c2:c8:95:dd:7b:46:56"
      )
}
