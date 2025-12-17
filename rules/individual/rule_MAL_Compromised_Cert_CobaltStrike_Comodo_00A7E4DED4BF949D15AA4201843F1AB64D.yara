import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Comodo_00A7E4DED4BF949D15AA4201843F1AB64D {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Comodo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2018-08-13"
      version             = "1.0"

      hash                = "2b083062d97753259ddd4015c806ecb06d121531e7a2807420d95df207c3154d"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "1.A Connect GmbH"
      cert_issuer_short   = "Comodo"
      cert_issuer         = "COMODO RSA Code Signing CA"
      cert_serial         = "00:a7:e4:de:d4:bf:94:9d:15:aa:42:01:84:3f:1a:b6:4d"
      cert_thumbprint     = "FC3F6D98724178B8A5BEE724858D22573B8DB97B"
      cert_valid_from     = "2018-08-13"
      cert_valid_to       = "2022-08-13"

      country             = "DE"
      state               = "Saarland"
      locality            = "Nohfelden"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "COMODO RSA Code Signing CA" and
         sig.serial == "00:a7:e4:de:d4:bf:94:9d:15:aa:42:01:84:3f:1a:b6:4d"
      )
}
