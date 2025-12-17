import "pe"

rule MAL_Compromised_Cert_SolarMarker_Certum_22B71B4E1DFFAF027DAD91DE93DD4E00 {
   meta:
      description         = "Detects SolarMarker with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-09-21"
      version             = "1.0"

      hash                = "18aeff0a97dfd33b6f0664f43ecafd18511af559002072f680a4e5929a9c7e4f"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "APPS HORIZON"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "22:b7:1b:4e:1d:ff:af:02:7d:ad:91:de:93:dd:4e:00"
      cert_thumbprint     = "08D3A8CE50220C140708317EE89AAF475795A4FB"
      cert_valid_from     = "2022-09-21"
      cert_valid_to       = "2023-09-21"

      country             = "FR"
      state               = "PARIS"
      locality            = "PARIS"
      email               = "???"
      rdn_serial_number   = "824789283"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "22:b7:1b:4e:1d:ff:af:02:7d:ad:91:de:93:dd:4e:00"
      )
}
