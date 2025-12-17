import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_GlobalSign_623D84F3FD52F1A872E1BF83 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-24"
      version             = "1.0"

      hash                = "ee4589553dadaae174dce6ce9b62804186717f24e9d01c8a41ed8643cc8024e9"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware leverages cloud hosting to hold additional components. The components are TASLogin and its associated DLL: medium.com/@anyrun/zhong-stealer-analysis-new-malware-targeting-fintech-and-cryptocurrency-71d4a3cce42c"

      signer              = "Shanghai Linyao Network Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "62:3d:84:f3:fd:52:f1:a8:72:e1:bf:83"
      cert_thumbprint     = "E565FD587547A22B363100369D6265E2E83842DF"
      cert_valid_from     = "2024-12-24"
      cert_valid_to       = "2025-12-24"

      country             = "CN"
      state               = "Shanghai"
      locality            = "Shanghai"
      email               = "???"
      rdn_serial_number   = "91310120MA1HY6532E"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "62:3d:84:f3:fd:52:f1:a8:72:e1:bf:83"
      )
}
