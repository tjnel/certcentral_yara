import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Sectigo_00AFF762E907F0644E76ED8A7485FB12A1 {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-05-27"
      version             = "1.0"

      hash                = "c786e4de11e64be8d4118cf8ba6b210e3396e3bb579f3afd4bf528c35bab4a6b"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "Lets Start SP Z O O"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:af:f7:62:e9:07:f0:64:4e:76:ed:8a:74:85:fb:12:a1"
      cert_thumbprint     = "2E23856699C852D258BF61EDF507C3362AE83BE3"
      cert_valid_from     = "2020-05-27"
      cert_valid_to       = "2021-05-27"

      country             = "PL"
      state               = "Warszawa"
      locality            = "Warszawa"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:af:f7:62:e9:07:f0:64:4e:76:ed:8a:74:85:fb:12:a1"
      )
}
