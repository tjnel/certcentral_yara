import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_2C18DB497B7FB347A85769E628C4DD00 {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-10-02"
      version             = "1.0"

      hash                = "a75819503eadb1816eee8884801d11ea7e8d1257ead704bca2aea42afe5edada"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "ТОВ \"Дефи\""
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "2c:18:db:49:7b:7f:b3:47:a8:57:69:e6:28:c4:dd:00"
      cert_thumbprint     = "8F0F2B6D0C3FC9D8B6B978A7B8F74DA8D6F8EE8C"
      cert_valid_from     = "2023-10-02"
      cert_valid_to       = "2024-10-01"

      country             = "UA"
      state               = "Dnipropetrovsk Oblast"
      locality            = "Dnipro"
      email               = "???"
      rdn_serial_number   = "45273271"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "2c:18:db:49:7b:7f:b3:47:a8:57:69:e6:28:c4:dd:00"
      )
}
