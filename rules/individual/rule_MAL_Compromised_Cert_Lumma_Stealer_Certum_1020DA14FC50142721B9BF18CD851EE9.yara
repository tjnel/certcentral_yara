import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_Certum_1020DA14FC50142721B9BF18CD851EE9 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-02"
      version             = "1.0"

      hash                = "fdacb443e59ed1b368f6d975ffd282b10fdbecb03950daac380a6864be25f2f8"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Weifang Bodu Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "10:20:da:14:fc:50:14:27:21:b9:bf:18:cd:85:1e:e9"
      cert_thumbprint     = "2B39470E15C59FB01F154A341709D3393CA0CD10"
      cert_valid_from     = "2024-10-02"
      cert_valid_to       = "2025-10-02"

      country             = "CN"
      state               = "Shandong"
      locality            = "Weifang"
      email               = "???"
      rdn_serial_number   = "91370725MA3DJ7DJ51"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "10:20:da:14:fc:50:14:27:21:b9:bf:18:cd:85:1e:e9"
      )
}
