import "pe"

rule MAL_Compromised_Cert_RomCom_Sectigo_00A05C0D563E8BC37162732DE6E1BFBF5C {
   meta:
      description         = "Detects RomCom with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-20"
      version             = "1.0"

      hash                = "be5327cc54087eceb1c61e09bc5153a811f6b0f13114d4ede45860794fe52c6f"
      malware             = "RomCom"
      malware_type        = "Backdoor"
      malware_notes       = "The malware is often disguised as a PDF and will launch an unrelated application when ran. See this for more details: https://www.bridewell.com/insights/blogs/detail/operation-deceptive-prospect-romcom-targeting-uk-organisations-through-customer-feedback-portals"

      signer              = "Qian'an Chengshuo Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:a0:5c:0d:56:3e:8b:c3:71:62:73:2d:e6:e1:bf:bf:5c"
      cert_thumbprint     = "BC16D3ADAE71054EFD1536BBF1A040D76EC26218"
      cert_valid_from     = "2025-10-20"
      cert_valid_to       = "2026-10-20"

      country             = "CN"
      state               = "Hebei Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:a0:5c:0d:56:3e:8b:c3:71:62:73:2d:e6:e1:bf:bf:5c"
      )
}
