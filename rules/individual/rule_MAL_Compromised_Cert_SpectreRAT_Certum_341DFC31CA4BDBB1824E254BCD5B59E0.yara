import "pe"

rule MAL_Compromised_Cert_SpectreRAT_Certum_341DFC31CA4BDBB1824E254BCD5B59E0 {
   meta:
      description         = "Detects SpectreRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-10"
      version             = "1.0"

      hash                = "84499164a4848a100a22361f38d36ddaea66d01d2e68580271692f9a6fc2a570"
      malware             = "SpectreRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xi'an Jiashi Xinnuo Information Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "34:1d:fc:31:ca:4b:db:b1:82:4e:25:4b:cd:5b:59:e0"
      cert_thumbprint     = "C2016ABA9447FCB75B03F158B31EAC7D76262377"
      cert_valid_from     = "2024-05-10"
      cert_valid_to       = "2025-05-10"

      country             = "CN"
      state               = "Shaanxi"
      locality            = "Xian"
      email               = "???"
      rdn_serial_number   = "91610113MA6TYLT60X"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "34:1d:fc:31:ca:4b:db:b1:82:4e:25:4b:cd:5b:59:e0"
      )
}
