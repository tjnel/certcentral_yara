import "pe"

rule MAL_Compromised_Cert_SolarMarker_GlobalSign_34D1F82D6B7BAE4075CEEEB7 {
   meta:
      description         = "Detects SolarMarker with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-10-27"
      version             = "1.0"

      hash                = "834c6ba26f460e98e9abad308eb261e2f23125d006573ec67b438d62eeabee60"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "JYL Business Solutions Inc."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "34:d1:f8:2d:6b:7b:ae:40:75:ce:ee:b7"
      cert_thumbprint     = "8D51D068E8EEF6AD1B111DAB77C433451235F052"
      cert_valid_from     = "2022-10-27"
      cert_valid_to       = "2023-10-28"

      country             = "CA"
      state               = "Ontario"
      locality            = "Woodbridge"
      email               = "???"
      rdn_serial_number   = "1007047-5"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "34:d1:f8:2d:6b:7b:ae:40:75:ce:ee:b7"
      )
}
