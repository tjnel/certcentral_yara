import "pe"

rule MAL_Compromised_Cert_SpectreRAT_Certum_711C937222514293ED01A76BC877B203 {
   meta:
      description         = "Detects SpectreRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-23"
      version             = "1.0"

      hash                = "bbbfdf66e9c773bcad95c6cd2e89a596620f417175de712269689b08f2643a40"
      malware             = "SpectreRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hefei Weimao Network Technology Co., Ltd"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "71:1c:93:72:22:51:42:93:ed:01:a7:6b:c8:77:b2:03"
      cert_thumbprint     = "63F84B5AE10552D7CF22D740F9C44F0FA9D029AE"
      cert_valid_from     = "2024-05-23"
      cert_valid_to       = "2025-05-23"

      country             = "CN"
      state               = "Anhui"
      locality            = "Hefei"
      email               = "???"
      rdn_serial_number   = "91340100083694107X"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "71:1c:93:72:22:51:42:93:ed:01:a7:6b:c8:77:b2:03"
      )
}
