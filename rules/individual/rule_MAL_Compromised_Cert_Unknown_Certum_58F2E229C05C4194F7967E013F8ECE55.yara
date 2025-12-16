import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_58F2E229C05C4194F7967E013F8ECE55 {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-16"
      version             = "1.0"

      hash                = "cea49f52c304557f201f79ce8031a392ee8f639feadc101f0c32ddd98373f57d"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Guangzhou Dongshui Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "58:f2:e2:29:c0:5c:41:94:f7:96:7e:01:3f:8e:ce:55"
      cert_thumbprint     = "640C80716EDF2D4628B18CFD07BED6DF2DA6EC94"
      cert_valid_from     = "2024-08-16"
      cert_valid_to       = "2025-08-16"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Guangzhou"
      email               = "???"
      rdn_serial_number   = "91440101MA9Y1HB49U"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "58:f2:e2:29:c0:5c:41:94:f7:96:7e:01:3f:8e:ce:55"
      )
}
