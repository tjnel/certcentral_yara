import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_71B5F261CB3D4563B9C7119FF093C098 {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-05-26"
      version             = "1.0"

      hash                = "1252f2bf3817714a8303f7e448930d6d4f797a70ec7effc80f2b1db5e49b9077"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Optimus"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "71:b5:f2:61:cb:3d:45:63:b9:c7:11:9f:f0:93:c0:98"
      cert_thumbprint     = "CFAAD6EA7F64D7665F8FE68AC24198E35FBF2CB9"
      cert_valid_from     = "2021-05-26"
      cert_valid_to       = "2022-10-16"

      country             = "RU"
      state               = "Novosibirsk Oblast"
      locality            = "Novosibirsk"
      email               = "???"
      rdn_serial_number   = "1195476035897"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "71:b5:f2:61:cb:3d:45:63:b9:c7:11:9f:f0:93:c0:98"
      )
}
