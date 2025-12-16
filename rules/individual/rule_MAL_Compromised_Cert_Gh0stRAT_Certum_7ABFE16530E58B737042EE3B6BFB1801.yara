import "pe"

rule MAL_Compromised_Cert_Gh0stRAT_Certum_7ABFE16530E58B737042EE3B6BFB1801 {
   meta:
      description         = "Detects Gh0stRAT with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-01"
      version             = "1.0"

      hash                = "e60b7e51420c59d34acd455907654dd2fdf9fc13d303f33e642b5da499fa7fb7"
      malware             = "Gh0stRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "烟台卡姆云信息科技有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "7a:bf:e1:65:30:e5:8b:73:70:42:ee:3b:6b:fb:18:01"
      cert_thumbprint     = "2B6BF84DED571DEF739F3E3AD7A8081AB380546C"
      cert_valid_from     = "2025-07-01"
      cert_valid_to       = "2026-07-01"

      country             = "CN"
      state               = "山东省"
      locality            = "烟台市"
      email               = "???"
      rdn_serial_number   = "91370613MACP97G01D"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "7a:bf:e1:65:30:e5:8b:73:70:42:ee:3b:6b:fb:18:01"
      )
}
