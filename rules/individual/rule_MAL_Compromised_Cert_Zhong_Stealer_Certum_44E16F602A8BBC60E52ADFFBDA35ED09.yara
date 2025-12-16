import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Certum_44E16F602A8BBC60E52ADFFBDA35ED09 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-27"
      version             = "1.0"

      hash                = "af982b9e203d5023b61f0a3758b1b1c1295ffa157d189a9eec3499f508d0e71d"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware leverages cloud hosting to hold additional components. The components are TASLogin and its associated DLL: medium.com/@anyrun/zhong-stealer-analysis-new-malware-targeting-fintech-and-cryptocurrency-71d4a3cce42c"

      signer              = "Wuhan Liansitong Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "44:e1:6f:60:2a:8b:bc:60:e5:2a:df:fb:da:35:ed:09"
      cert_thumbprint     = "3F5EF573974902B64A70A6A6A6E030752E8E4086"
      cert_valid_from     = "2025-10-27"
      cert_valid_to       = "2026-10-27"

      country             = "CN"
      state               = "湖北省"
      locality            = "武汉市"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "44:e1:6f:60:2a:8b:bc:60:e5:2a:df:fb:da:35:ed:09"
      )
}
