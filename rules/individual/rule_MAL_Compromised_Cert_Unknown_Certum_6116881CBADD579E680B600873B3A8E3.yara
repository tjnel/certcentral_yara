import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_6116881CBADD579E680B600873B3A8E3 {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-13"
      version             = "1.0"

      hash                = "0dbeb3173cf0f5551f4e118083a95bdeb4eda4189f28bf2c7ad5f3c899642912"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Guangdong Kenuosi IoT Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "61:16:88:1c:ba:dd:57:9e:68:0b:60:08:73:b3:a8:e3"
      cert_thumbprint     = "8939F7E15BAAD7662495E6DCCFC1D320F25F7558"
      cert_valid_from     = "2024-09-13"
      cert_valid_to       = "2025-09-13"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Dongguan"
      email               = "???"
      rdn_serial_number   = "91441900MA54J07X80"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "61:16:88:1c:ba:dd:57:9e:68:0b:60:08:73:b3:a8:e3"
      )
}
