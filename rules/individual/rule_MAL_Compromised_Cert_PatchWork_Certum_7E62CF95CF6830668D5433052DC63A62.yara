import "pe"

rule MAL_Compromised_Cert_PatchWork_Certum_7E62CF95CF6830668D5433052DC63A62 {
   meta:
      description         = "Detects PatchWork with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-08"
      version             = "1.0"

      hash                = "fb75316e371b73eec437e2a0a997f4d04eaca78f7a36cba7b71095d75e4aae01"
      malware             = "PatchWork"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xi'an Qinxuntao Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "7e:62:cf:95:cf:68:30:66:8d:54:33:05:2d:c6:3a:62"
      cert_thumbprint     = "DC0370E05588243E8F5C0D116CA2F76459C6BEBF"
      cert_valid_from     = "2024-05-08"
      cert_valid_to       = "2025-05-08"

      country             = "CN"
      state               = "Shaanxi"
      locality            = "Xian"
      email               = "???"
      rdn_serial_number   = "91610113MA6X13GR4H"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "7e:62:cf:95:cf:68:30:66:8d:54:33:05:2d:c6:3a:62"
      )
}
