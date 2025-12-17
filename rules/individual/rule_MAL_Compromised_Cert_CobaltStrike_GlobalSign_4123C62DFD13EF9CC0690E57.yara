import "pe"

rule MAL_Compromised_Cert_CobaltStrike_GlobalSign_4123C62DFD13EF9CC0690E57 {
   meta:
      description         = "Detects CobaltStrike with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-05"
      version             = "1.0"

      hash                = "23d331f8dafd75e487b12295f49914bb37a63df04c9f7ffda89c9bd2418ddf87"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "ANALYZER ENTERPRISES LLP"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "41:23:c6:2d:fd:13:ef:9c:c0:69:0e:57"
      cert_thumbprint     = "fc247e295ce9be12a1ffd204fccb4f1e76919b3d455efe7f25b91fc2a22379fd"
      cert_valid_from     = "2024-11-05"
      cert_valid_to       = "2025-11-06"

      country             = "IN"
      state               = "Rajasthan"
      locality            = "Jaipur"
      email               = "fvakdu@gmail.com"
      rdn_serial_number   = "AAO-5256"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "41:23:c6:2d:fd:13:ef:9c:c0:69:0e:57"
      )
}
