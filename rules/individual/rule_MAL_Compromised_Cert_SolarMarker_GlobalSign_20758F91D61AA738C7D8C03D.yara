import "pe"

rule MAL_Compromised_Cert_SolarMarker_GlobalSign_20758F91D61AA738C7D8C03D {
   meta:
      description         = "Detects SolarMarker with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-07-31"
      version             = "1.0"

      hash                = "e89360d7d77e6979d54dc567cee54ac6128b8ed9250bc3164c5e77c43cd8a647"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "RUBEZH LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "20:75:8f:91:d6:1a:a7:38:c7:d8:c0:3d"
      cert_thumbprint     = "B34163285DB484E5C2FFBFE56D3A08265AA950BC"
      cert_valid_from     = "2023-07-31"
      cert_valid_to       = "2024-07-31"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1237700057946"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "20:75:8f:91:d6:1a:a7:38:c7:d8:c0:3d"
      )
}
