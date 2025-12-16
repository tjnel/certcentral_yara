import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_Certum_468FFDEA6B0AAC7709BC66E3E5A9CE1A {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-28"
      version             = "1.0"

      hash                = "4f986320f90db5e745bcc343080a6aa371c6d6c067501a1c898920ca50ba24d1"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Anhui Wansanshi Internet of Things Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "46:8f:fd:ea:6b:0a:ac:77:09:bc:66:e3:e5:a9:ce:1a"
      cert_thumbprint     = "8A63640C6C4902126CBBC41F1C221679E40D3F28"
      cert_valid_from     = "2024-05-28"
      cert_valid_to       = "2025-05-28"

      country             = "CN"
      state               = "Anhui"
      locality            = "Wuhu"
      email               = "???"
      rdn_serial_number   = "91340222MA2MXM3F23"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "46:8f:fd:ea:6b:0a:ac:77:09:bc:66:e3:e5:a9:ce:1a"
      )
}
