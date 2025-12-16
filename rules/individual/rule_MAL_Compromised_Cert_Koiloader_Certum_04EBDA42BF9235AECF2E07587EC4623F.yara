import "pe"

rule MAL_Compromised_Cert_Koiloader_Certum_04EBDA42BF9235AECF2E07587EC4623F {
   meta:
      description         = "Detects Koiloader with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-21"
      version             = "1.0"

      hash                = "e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819"
      malware             = "Koiloader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Zhengzhou Lichang Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "04:eb:da:42:bf:92:35:ae:cf:2e:07:58:7e:c4:62:3f"
      cert_thumbprint     = "B78EDD5FFE3A45F2993E98F9CCE5F0187EE880BD"
      cert_valid_from     = "2024-11-21"
      cert_valid_to       = "2025-11-21"

      country             = "CN"
      state               = "Henan"
      locality            = "Zhengzhou"
      email               = "???"
      rdn_serial_number   = "91410122MA40Y0N9XP"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "04:eb:da:42:bf:92:35:ae:cf:2e:07:58:7e:c4:62:3f"
      )
}
