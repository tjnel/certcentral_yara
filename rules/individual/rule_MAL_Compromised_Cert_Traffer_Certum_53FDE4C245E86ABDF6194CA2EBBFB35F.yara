import "pe"

rule MAL_Compromised_Cert_Traffer_Certum_53FDE4C245E86ABDF6194CA2EBBFB35F {
   meta:
      description         = "Detects Traffer with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-07"
      version             = "1.0"

      hash                = "65a97735e27b6f493c47b1ccdafbf94065e09448e4a9e51b0dbc1d4e7b22c3c0"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Nanjing Bangqiao Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "53:fd:e4:c2:45:e8:6a:bd:f6:19:4c:a2:eb:bf:b3:5f"
      cert_thumbprint     = "248C1A34A639DC481C7A7C28AF6C78578481050D"
      cert_valid_from     = "2025-08-07"
      cert_valid_to       = "2026-08-07"

      country             = "CN"
      state               = "江苏省"
      locality            = "南京市"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "53:fd:e4:c2:45:e8:6a:bd:f6:19:4c:a2:eb:bf:b3:5f"
      )
}
