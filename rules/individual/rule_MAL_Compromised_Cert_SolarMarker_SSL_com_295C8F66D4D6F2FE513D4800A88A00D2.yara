import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_295C8F66D4D6F2FE513D4800A88A00D2 {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-11-11"
      version             = "1.0"

      hash                = "b68a65e9f8cb6aff77c8d1973e60063de53ca052ee6c98919c96decf5ef705a8"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "ТОВ \"Трейдинг Комфорт\""
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "29:5c:8f:66:d4:d6:f2:fe:51:3d:48:00:a8:8a:00:d2"
      cert_thumbprint     = "6BDC8E5A1739BFF3F4FD0E866A281823DBED967B"
      cert_valid_from     = "2023-11-11"
      cert_valid_to       = "2024-11-09"

      country             = "UA"
      state               = "Zhytomyr Oblast"
      locality            = "Zhytomyr"
      email               = "???"
      rdn_serial_number   = "45291589"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "29:5c:8f:66:d4:d6:f2:fe:51:3d:48:00:a8:8a:00:d2"
      )
}
