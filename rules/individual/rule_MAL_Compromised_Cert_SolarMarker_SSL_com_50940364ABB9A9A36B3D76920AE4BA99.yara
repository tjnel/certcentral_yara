import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_50940364ABB9A9A36B3D76920AE4BA99 {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-08-30"
      version             = "1.0"

      hash                = "a82a9e1f6667350808a19219d586d10bcea85cf73b67024d8c58366981fe4993"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Game Warriors Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "50:94:03:64:ab:b9:a9:a3:6b:3d:76:92:0a:e4:ba:99"
      cert_thumbprint     = "F1BABD3CDCA991FB45744D04751E98DF0FACB1DF"
      cert_valid_from     = "2022-08-30"
      cert_valid_to       = "2023-08-30"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "12348358"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "50:94:03:64:ab:b9:a9:a3:6b:3d:76:92:0a:e4:ba:99"
      )
}
