import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_2A17239F25F18AA969D76DEC4722598D {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-10-18"
      version             = "1.0"

      hash                = "a24bc1178a53b6afb67d802a2adb2ab48a9f203e9c6da756323a3178b0b6d02c"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "ТОВ \"Гемінг сапорт\""
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "2a:17:23:9f:25:f1:8a:a9:69:d7:6d:ec:47:22:59:8d"
      cert_thumbprint     = "54A87FD5519B87CAEFFF72A1EF8C14E734E733E0"
      cert_valid_from     = "2023-10-18"
      cert_valid_to       = "2024-10-17"

      country             = "UA"
      state               = "Kiev"
      locality            = "Kyiv"
      email               = "???"
      rdn_serial_number   = "45190735"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "2a:17:23:9f:25:f1:8a:a9:69:d7:6d:ec:47:22:59:8d"
      )
}
