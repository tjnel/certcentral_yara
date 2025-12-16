import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Sectigo_00EE3A88EF4AB47D8617E4EDC56736C75F {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-28"
      version             = "1.0"

      hash                = "441ef8aa13409660cedb9a557619f60cbf90c3f0d28f7191b8385a6d147acf46"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware leverages cloud hosting to hold additional components. The components are TASLogin and its associated DLL: medium.com/@anyrun/zhong-stealer-analysis-new-malware-targeting-fintech-and-cryptocurrency-71d4a3cce42c"

      signer              = "邢台鸭梨智能科技有限公司"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:ee:3a:88:ef:4a:b4:7d:86:17:e4:ed:c5:67:36:c7:5f"
      cert_thumbprint     = "1F4036E52F236004A8229D7AD0E18024423044B9"
      cert_valid_from     = "2024-11-28"
      cert_valid_to       = "2025-11-28"

      country             = "CN"
      state               = "河北省"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:ee:3a:88:ef:4a:b4:7d:86:17:e4:ed:c5:67:36:c7:5f"
      )
}
