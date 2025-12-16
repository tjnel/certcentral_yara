import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_6FE721C3DDBD2774D03DCEA44A26A78A {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-09-29"
      version             = "1.0"

      hash                = "1e7914f799371cbc8560bc52203d3531bb20cb4f6092158c76a4842dbf85dabc"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "OOO ENDI"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "6f:e7:21:c3:dd:bd:27:74:d0:3d:ce:a4:4a:26:a7:8a"
      cert_thumbprint     = "BC346A6BF6B6D53A69A742A4245A43320980B1C0"
      cert_valid_from     = "2021-09-29"
      cert_valid_to       = "2022-09-29"

      country             = "RU"
      state               = "Saint Petersburg"
      locality            = "Saint Petersburg"
      email               = "???"
      rdn_serial_number   = "1097847161631"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "6f:e7:21:c3:dd:bd:27:74:d0:3d:ce:a4:4a:26:a7:8a"
      )
}
