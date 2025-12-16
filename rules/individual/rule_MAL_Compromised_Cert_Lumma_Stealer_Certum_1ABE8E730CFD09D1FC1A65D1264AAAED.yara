import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_Certum_1ABE8E730CFD09D1FC1A65D1264AAAED {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-02"
      version             = "1.0"

      hash                = "dd5566e9a9d1cf5dc37c88cb33c1324dbc3de0c4af22d2f00cadaf7d07f1b4c8"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Shenzhen Xinshitong Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "1a:be:8e:73:0c:fd:09:d1:fc:1a:65:d1:26:4a:aa:ed"
      cert_thumbprint     = "8F44A139359DDB9310C681526C560F207B706115"
      cert_valid_from     = "2024-10-02"
      cert_valid_to       = "2025-10-02"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Shenzhen"
      email               = "???"
      rdn_serial_number   = "914403003426869970"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "1a:be:8e:73:0c:fd:09:d1:fc:1a:65:d1:26:4a:aa:ed"
      )
}
