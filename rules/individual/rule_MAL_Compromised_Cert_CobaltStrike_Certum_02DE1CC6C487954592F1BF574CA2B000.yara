import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Certum_02DE1CC6C487954592F1BF574CA2B000 {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-02-19"
      version             = "1.0"

      hash                = "6b9b5df993a38ebb2fa3eba4c26686b49aa57ec577902222225058a02284170e"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "Orca System"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing CA SHA2"
      cert_serial         = "02:de:1c:c6:c4:87:95:45:92:f1:bf:57:4c:a2:b0:00"
      cert_thumbprint     = "E35804BBF4573F492C51A7AD7A14557816FE961F"
      cert_valid_from     = "2021-02-19"
      cert_valid_to       = "2022-02-19"

      country             = "FR"
      state               = "Paris"
      locality            = "Paris"
      email               = "???"
      rdn_serial_number   = "430053835"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing CA SHA2" and
         sig.serial == "02:de:1c:c6:c4:87:95:45:92:f1:bf:57:4c:a2:b0:00"
      )
}
