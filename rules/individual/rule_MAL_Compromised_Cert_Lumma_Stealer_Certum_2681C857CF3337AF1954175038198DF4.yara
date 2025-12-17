import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_Certum_2681C857CF3337AF1954175038198DF4 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-13"
      version             = "1.0"

      hash                = "397a2d0a1f7c975eaf2724a411a1cfbe63a64e20520a8e9ea78d0c7b60ae6b8c"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Chengdu Daodaotong Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "26:81:c8:57:cf:33:37:af:19:54:17:50:38:19:8d:f4"
      cert_thumbprint     = "9E743FCBDDF9AB9134BD0ED157D4FBA99606F54F"
      cert_valid_from     = "2024-09-13"
      cert_valid_to       = "2025-09-13"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Chengdu"
      email               = "???"
      rdn_serial_number   = "91510107394612965F"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "26:81:c8:57:cf:33:37:af:19:54:17:50:38:19:8d:f4"
      )
}
