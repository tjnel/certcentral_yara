import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_055C02563838CEA7452A07111BBA010D {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-05-28"
      version             = "1.0"

      hash                = "29014a3438c174c2e7377168adf62080e7566e1664c1b639e454a9ad961b5fde"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Verbtronic Digital Inc."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "05:5c:02:56:38:38:ce:a7:45:2a:07:11:1b:ba:01:0d"
      cert_thumbprint     = "6A5CC3062EF8CB193381E51C34C0467A0F1C9405"
      cert_valid_from     = "2022-05-28"
      cert_valid_to       = "2023-05-27"

      country             = "CA"
      state               = "Ontario"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "1247352-6"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "05:5c:02:56:38:38:ce:a7:45:2a:07:11:1b:ba:01:0d"
      )
}
