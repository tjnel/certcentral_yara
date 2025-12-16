import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Sectigo_2DCD0699DA08915DDE6D044CB474157C {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-09-21"
      version             = "1.0"

      hash                = "b568a4ca18fce49b465d0db8697640d556f579932db0315398a810140c66f0db"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "VENTE DE TOUT"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "2d:cd:06:99:da:08:91:5d:de:6d:04:4c:b4:74:15:7c"
      cert_thumbprint     = "3B4470D37D93CA1C15224413672349200F1A51EA"
      cert_valid_from     = "2020-09-21"
      cert_valid_to       = "2021-09-21"

      country             = "FR"
      state               = "???"
      locality            = "POISSY"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "2d:cd:06:99:da:08:91:5d:de:6d:04:4c:b4:74:15:7c"
      )
}
