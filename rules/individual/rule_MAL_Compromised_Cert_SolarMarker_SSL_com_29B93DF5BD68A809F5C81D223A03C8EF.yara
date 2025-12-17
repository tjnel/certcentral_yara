import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_29B93DF5BD68A809F5C81D223A03C8EF {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-09-12"
      version             = "1.0"

      hash                = "32e0c3db78cdeaa026b8b9ed9c3e4f599eb5d9cb4184aaacae8ec94a0c1be438"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "ТОВ \"Чеб\""
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "29:b9:3d:f5:bd:68:a8:09:f5:c8:1d:22:3a:03:c8:ef"
      cert_thumbprint     = "D593CC3E922DA5C4B9EF4075A9212C0B698046E6"
      cert_valid_from     = "2023-09-12"
      cert_valid_to       = "2024-09-11"

      country             = "UA"
      state               = "Dnipropetrovsk Oblast"
      locality            = "Novomoskovsk Raion"
      email               = "???"
      rdn_serial_number   = "45285135"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "29:b9:3d:f5:bd:68:a8:09:f5:c8:1d:22:3a:03:c8:ef"
      )
}
