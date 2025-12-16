import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_157EF6D6D74883FE50765D9DA9E11C69 {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-12-07"
      version             = "1.0"

      hash                = "6c89c09213a79a917a97f4531b9ef01da8feee805d2d3b7de92a831dbec9a7e6"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "ТОВ \"Тотоп\""
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "15:7e:f6:d6:d7:48:83:fe:50:76:5d:9d:a9:e1:1c:69"
      cert_thumbprint     = "BD6904484A52B6F0779D957C12C0E57B3546BA20"
      cert_valid_from     = "2023-12-07"
      cert_valid_to       = "2024-12-06"

      country             = "UA"
      state               = "Dnipropetrovsk Oblast"
      locality            = "Dnipro"
      email               = "???"
      rdn_serial_number   = "45213322"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "15:7e:f6:d6:d7:48:83:fe:50:76:5d:9d:a9:e1:1c:69"
      )
}
