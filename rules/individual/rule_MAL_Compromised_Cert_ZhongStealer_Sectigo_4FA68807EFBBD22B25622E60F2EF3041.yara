import "pe"

rule MAL_Compromised_Cert_ZhongStealer_Sectigo_4FA68807EFBBD22B25622E60F2EF3041 {
   meta:
      description         = "Detects ZhongStealer with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-11"
      version             = "1.0"

      hash                = "be5d6c4aa4b27548a06c2afaef3b4035abf65566e9a8bfd642b4a2032729656e"
      malware             = "ZhongStealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware leverages cloud hosting to hold additional components. The components are TASLogin and its associated DLL: medium.com/@anyrun/zhong-stealer-analysis-new-malware-targeting-fintech-and-cryptocurrency-71d4a3cce42c"

      signer              = "运城市盐湖区风颜商贸有限公司"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "4f:a6:88:07:ef:bb:d2:2b:25:62:2e:60:f2:ef:30:41"
      cert_thumbprint     = "A176736F8B6462141E4BFDFC1FEB5EC11663D684"
      cert_valid_from     = "2025-02-11"
      cert_valid_to       = "2026-05-12"

      country             = "CN"
      state               = "山西省"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91140802MADALQC44B"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "4f:a6:88:07:ef:bb:d2:2b:25:62:2e:60:f2:ef:30:41"
      )
}
