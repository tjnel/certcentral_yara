import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_4A8EDE8C9A2A4D6E4E715914F57625FE {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-09-01"
      version             = "1.0"

      hash                = "9d215743885b4f6d937deb0975c1b4b7a771d2d1c67a958b18f28383756bafc2"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "ТОВ \"Ред Драгон Девелоп\""
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "4a:8e:de:8c:9a:2a:4d:6e:4e:71:59:14:f5:76:25:fe"
      cert_thumbprint     = "CEAC5151942E41A43CA361CB52F2F3B9842CA186"
      cert_valid_from     = "2023-09-01"
      cert_valid_to       = "2024-08-31"

      country             = "UA"
      state               = "???"
      locality            = "Zhytomyr"
      email               = "???"
      rdn_serial_number   = "45226834"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "4a:8e:de:8c:9a:2a:4d:6e:4e:71:59:14:f5:76:25:fe"
      )
}
