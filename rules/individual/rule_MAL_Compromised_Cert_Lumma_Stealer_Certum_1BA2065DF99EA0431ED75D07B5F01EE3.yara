import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_Certum_1BA2065DF99EA0431ED75D07B5F01EE3 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-27"
      version             = "1.0"

      hash                = "59cbdbc57cfd1a2b8014a0572001ee5583856c7479539305110dd5ee09d77d7f"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Guangzhou Wenlong Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "1b:a2:06:5d:f9:9e:a0:43:1e:d7:5d:07:b5:f0:1e:e3"
      cert_thumbprint     = "3C2B0899E92BC1235B554F3171DF124CF9B5F829"
      cert_valid_from     = "2024-09-27"
      cert_valid_to       = "2025-09-27"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Guangzhou"
      email               = "???"
      rdn_serial_number   = "91440101072117953U"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "1b:a2:06:5d:f9:9e:a0:43:1e:d7:5d:07:b5:f0:1e:e3"
      )
}
