import "pe"

rule MAL_Compromised_Cert_BatLoader_Certum_218A79C93C595847559394CCE196B383 {
   meta:
      description         = "Detects BatLoader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-07"
      version             = "1.0"

      hash                = "7565bd4a85a95a5789d47e7c74756c38490c4ed5a6432bf7bab4fb4c289024c5"
      malware             = "BatLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "See this article to learn more about Batloader: https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html"

      signer              = "Guangzhou Yongwu Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "21:8a:79:c9:3c:59:58:47:55:93:94:cc:e1:96:b3:83"
      cert_thumbprint     = "CE1A300B46F31EDEB192CC2D65EFD86D5063618D"
      cert_valid_from     = "2024-08-07"
      cert_valid_to       = "2025-08-07"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Guangzhou"
      email               = "???"
      rdn_serial_number   = "91440101MA9URAWW0Q"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "21:8a:79:c9:3c:59:58:47:55:93:94:cc:e1:96:b3:83"
      )
}
