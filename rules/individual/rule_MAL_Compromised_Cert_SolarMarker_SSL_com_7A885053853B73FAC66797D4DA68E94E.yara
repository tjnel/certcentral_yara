import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_7A885053853B73FAC66797D4DA68E94E {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-07-11"
      version             = "1.0"

      hash                = "65569db0dceb1c06be2a2cccedfef1447d14ec6d6f3d5ce28c4997c45c4991a8"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "TOV RT RUNA"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "7a:88:50:53:85:3b:73:fa:c6:67:97:d4:da:68:e9:4e"
      cert_thumbprint     = "F5324F7D7383D03530958E94A468DAA00F80087E"
      cert_valid_from     = "2023-07-11"
      cert_valid_to       = "2024-07-10"

      country             = "UA"
      state               = "Dnipropetrovsk Oblast"
      locality            = "Kamianske"
      email               = "???"
      rdn_serial_number   = "44925256"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "7a:88:50:53:85:3b:73:fa:c6:67:97:d4:da:68:e9:4e"
      )
}
