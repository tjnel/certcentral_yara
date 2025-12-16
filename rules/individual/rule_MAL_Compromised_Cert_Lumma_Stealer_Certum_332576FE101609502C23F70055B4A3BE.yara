import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_Certum_332576FE101609502C23F70055B4A3BE {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-09"
      version             = "1.0"

      hash                = "193f942ae9f7d2f75324b7b9fc27b98dfb3df1b7802ffcd4aa8ce2c248ae09e4"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Guizhou Sixuanda Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "33:25:76:fe:10:16:09:50:2c:23:f7:00:55:b4:a3:be"
      cert_thumbprint     = "A3AFF46C5F8E2A1F750C570698B864E75553E61F"
      cert_valid_from     = "2024-09-09"
      cert_valid_to       = "2025-09-09"

      country             = "CN"
      state               = "Guizhou"
      locality            = "Guiyang"
      email               = "???"
      rdn_serial_number   = "91520100MA6DNNXK11"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "33:25:76:fe:10:16:09:50:2c:23:f7:00:55:b4:a3:be"
      )
}
