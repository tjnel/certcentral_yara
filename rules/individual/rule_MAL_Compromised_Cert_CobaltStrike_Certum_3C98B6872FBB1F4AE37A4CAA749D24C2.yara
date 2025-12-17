import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Certum_3C98B6872FBB1F4AE37A4CAA749D24C2 {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-02-15"
      version             = "1.0"

      hash                = "a93eb70cc4152e32cd3a39fda968b2da5ade48453927410a0d520f2d13223d11"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "OOO SMART"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing CA SHA2"
      cert_serial         = "3c:98:b6:87:2f:bb:1f:4a:e3:7a:4c:aa:74:9d:24:c2"
      cert_thumbprint     = "757E0FBBED8ABE068C00A1467C047D44FC4A6FE5"
      cert_valid_from     = "2021-02-15"
      cert_valid_to       = "2022-02-15"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1117746597649"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing CA SHA2" and
         sig.serial == "3c:98:b6:87:2f:bb:1f:4a:e3:7a:4c:aa:74:9d:24:c2"
      )
}
