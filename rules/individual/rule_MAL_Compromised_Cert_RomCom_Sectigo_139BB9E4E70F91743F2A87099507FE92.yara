import "pe"

rule MAL_Compromised_Cert_RomCom_Sectigo_139BB9E4E70F91743F2A87099507FE92 {
   meta:
      description         = "Detects RomCom with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-14"
      version             = "1.0"

      hash                = "8c2def9d3346a1f96b43c8a915d9585e742351b05a1887b2ec4293712eb64af7"
      malware             = "RomCom"
      malware_type        = "Backdoor"
      malware_notes       = "The malware is often disguised as a PDF and will launch an unrelated application when ran. See this for more details: https://www.bridewell.com/insights/blogs/detail/operation-deceptive-prospect-romcom-targeting-uk-organisations-through-customer-feedback-portals"

      signer              = "Mianyang Zhishuo Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "13:9b:b9:e4:e7:0f:91:74:3f:2a:87:09:95:07:fe:92"
      cert_thumbprint     = "EA27F933184E7F4398166F950C6E9541C332F7EC"
      cert_valid_from     = "2025-11-14"
      cert_valid_to       = "2026-11-14"

      country             = "CN"
      state               = "Sichuan Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "13:9b:b9:e4:e7:0f:91:74:3f:2a:87:09:95:07:fe:92"
      )
}
