import "pe"

rule MAL_Compromised_Cert_SolarMarker_GlobalSign_6C4ED4D7E425DD681FA71F59 {
   meta:
      description         = "Detects SolarMarker with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-05-24"
      version             = "1.0"

      hash                = "a13278be27e4b0c38d7102496f3d4fcfb31cf710389edee244a4c5dd40055c4f"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "MORYS LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "6c:4e:d4:d7:e4:25:dd:68:1f:a7:1f:59"
      cert_thumbprint     = "40F9FBB664B23C52FD766376B48B543E798C3AC5"
      cert_valid_from     = "2023-05-24"
      cert_valid_to       = "2024-05-24"

      country             = "RU"
      state               = "Leningrad Oblast"
      locality            = "Murino"
      email               = "???"
      rdn_serial_number   = "1234700011391"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "6c:4e:d4:d7:e4:25:dd:68:1f:a7:1f:59"
      )
}
