import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Sectigo_29128A56E7B3BFB230742591AC8B4718 {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-05-14"
      version             = "1.0"

      hash                = "d80026d7e9397366ff4d2eeddd01421843e4d9898df1360267c1616ea59fcc56"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "Programavimo paslaugos, MB"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "29:12:8a:56:e7:b3:bf:b2:30:74:25:91:ac:8b:47:18"
      cert_thumbprint     = "18C01A6422F2679127E4974F9DD408D5CACC0428"
      cert_valid_from     = "2020-05-14"
      cert_valid_to       = "2021-05-14"

      country             = "LT"
      state               = "Vilnius"
      locality            = "Vilnius"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "29:12:8a:56:e7:b3:bf:b2:30:74:25:91:ac:8b:47:18"
      )
}
