import "pe"

rule MAL_Compromised_Cert_SecTopRAT_ArechClient2_Certum_529DA3EA8D3FDD03C4BA1ACF5729E0CE {
   meta:
      description         = "Detects SecTopRAT,ArechClient2 with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-17"
      version             = "1.0"

      hash                = "8fa9074cd74cbcedc44b12999dbc5f4e51ea82caa24be18b073686229f1f9db8"
      malware             = "SecTopRAT,ArechClient2"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Open Source Developer, Martijn Laan"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "52:9d:a3:ea:8d:3f:dd:03:c4:ba:1a:cf:57:29:e0:ce"
      cert_thumbprint     = "2514B6114FBBD66B24E6D171B428464B903C33D9"
      cert_valid_from     = "2024-04-17"
      cert_valid_to       = "2025-04-17"

      country             = "NL"
      state               = "Noord-Holland"
      locality            = "Aalsmeer"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "52:9d:a3:ea:8d:3f:dd:03:c4:ba:1a:cf:57:29:e0:ce"
      )
}
