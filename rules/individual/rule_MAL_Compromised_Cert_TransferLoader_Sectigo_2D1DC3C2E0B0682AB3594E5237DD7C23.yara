import "pe"

rule MAL_Compromised_Cert_TransferLoader_Sectigo_2D1DC3C2E0B0682AB3594E5237DD7C23 {
   meta:
      description         = "Detects TransferLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-22"
      version             = "1.0"

      hash                = "ca4890fb8c7b69bb75b522746e2e96ce8b4459ff1fa25c679bc13f1183230b70"
      malware             = "TransferLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware was disguised as a resume and a PDF. It uses a PDF as a decoy. See this blog for more details on the malware family: https://www.zscaler.com/blogs/security-research/technical-analysis-transferloader"

      signer              = "Dongguan Yingping Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "2d:1d:c3:c2:e0:b0:68:2a:b3:59:4e:52:37:dd:7c:23"
      cert_thumbprint     = "7440B35E9B9E3140A702AA5A182A7D1869F73462"
      cert_valid_from     = "2025-10-22"
      cert_valid_to       = "2027-01-20"

      country             = "CN"
      state               = "Guangdong Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "2d:1d:c3:c2:e0:b0:68:2a:b3:59:4e:52:37:dd:7c:23"
      )
}
