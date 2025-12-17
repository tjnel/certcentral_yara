import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_6ADA64000BBAF0497538A2BF1938F2BA {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-11-06"
      version             = "1.0"

      hash                = "9dc4e8a0d45b04b1b4bc2df2a16aa37e5597624feed3b53a9c5ca2929a2fb6c3"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "ТОВ \"Оноп\""
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "6a:da:64:00:0b:ba:f0:49:75:38:a2:bf:19:38:f2:ba"
      cert_thumbprint     = "96450C6F02D7E314EE2A20330D01E6A502325033"
      cert_valid_from     = "2023-11-06"
      cert_valid_to       = "2024-11-05"

      country             = "UA"
      state               = "Dnipropetrovsk Oblast"
      locality            = "Dnipro"
      email               = "???"
      rdn_serial_number   = "45364405"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "6a:da:64:00:0b:ba:f0:49:75:38:a2:bf:19:38:f2:ba"
      )
}
