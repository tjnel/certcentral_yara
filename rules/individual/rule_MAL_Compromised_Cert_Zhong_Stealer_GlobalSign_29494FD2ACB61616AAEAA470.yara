import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_GlobalSign_29494FD2ACB61616AAEAA470 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-20"
      version             = "1.0"

      hash                = "d19ca1798eaa49f3a803294d240c7bcf121b8c1f0f261aa7d7a30011fafb2385"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware leverages cloud hosting to hold additional components. The components are TASLogin and its associated DLL: medium.com/@anyrun/zhong-stealer-analysis-new-malware-targeting-fintech-and-cryptocurrency-71d4a3cce42c"

      signer              = "Taiyuan Jiedong Trading Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "29:49:4f:d2:ac:b6:16:16:aa:ea:a4:70"
      cert_thumbprint     = "3B0BB0BB9C0B9E86454C6D2EBE5A8D93E7D8DD92"
      cert_valid_from     = "2025-05-20"
      cert_valid_to       = "2026-05-21"

      country             = "CN"
      state               = "Shanxi"
      locality            = "Taiyuan"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "29:49:4f:d2:ac:b6:16:16:aa:ea:a4:70"
      )
}
