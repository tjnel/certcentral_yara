import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Certum_5AE3A3B23CFA63ADFCED9BA9EF9A263C {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-21"
      version             = "1.0"

      hash                = "179b8af13000463b87f74c99828671f0069126fc4cf65d862c223e67991ff75b"
      malware             = "Zhong Stealer"
      malware_type        = "Stealer"
      malware_notes       = ""

      signer              = "Jinhua Suyu Intelligent Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "5a:e3:a3:b2:3c:fa:63:ad:fc:ed:9b:a9:ef:9a:26:3c"
      cert_thumbprint     = "63813F758626A4071E571FA846955DF793961D7B"
      cert_valid_from     = "2025-11-21"
      cert_valid_to       = "2026-11-21"

      country             = "CN"
      state               = "浙江省"
      locality            = "金华市"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "5a:e3:a3:b2:3c:fa:63:ad:fc:ed:9b:a9:ef:9a:26:3c"
      )
}
