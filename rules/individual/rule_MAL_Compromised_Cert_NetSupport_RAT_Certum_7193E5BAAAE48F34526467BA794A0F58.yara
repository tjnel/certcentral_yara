import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_Certum_7193E5BAAAE48F34526467BA794A0F58 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-01"
      version             = "1.0"

      hash                = "7f4aca86b3ac80d29bb34801c48fb6a5a34887d4b76e9c16e4e080c16c23819a"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Destiny Software Sp. z o.o."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "71:93:e5:ba:aa:e4:8f:34:52:64:67:ba:79:4a:0f:58"
      cert_thumbprint     = "F62D3C51E6F9BEC0C7184FB43BE990D5F69884FE"
      cert_valid_from     = "2024-10-01"
      cert_valid_to       = "2025-10-01"

      country             = "PL"
      state               = "???"
      locality            = "Zielona Gora"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "71:93:e5:ba:aa:e4:8f:34:52:64:67:ba:79:4a:0f:58"
      )
}
