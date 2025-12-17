import "pe"

rule MAL_Compromised_Cert_Patchwork_Certum_23C462C35AFF4789FF24599B0EBC6BE9 {
   meta:
      description         = "Detects Patchwork with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-28"
      version             = "1.0"

      hash                = "e6071ae0da3289eb87edf67b2b198b0a3f0cf9da8eb35a8a2b5aa8989b6c0ef5"
      malware             = "Patchwork"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shandong Hongfu Information Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "23:c4:62:c3:5a:ff:47:89:ff:24:59:9b:0e:bc:6b:e9"
      cert_thumbprint     = "B915200E731D43F900D57AF7A2DE8467638282CA"
      cert_valid_from     = "2024-06-28"
      cert_valid_to       = "2025-06-28"

      country             = "CN"
      state               = "Shandong"
      locality            = "Linyi"
      email               = "???"
      rdn_serial_number   = "91371311MA3UWD0J5J"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "23:c4:62:c3:5a:ff:47:89:ff:24:59:9b:0e:bc:6b:e9"
      )
}
