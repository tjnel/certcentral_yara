import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Sectigo_009272607CFC982B782A5D36C4B78F5E7B {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-11-12"
      version             = "1.0"

      hash                = "3cd9b8f675d4718c4d73a9b1656836790a058b8ba46c1e0f254d46775ab06556"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "Rada SP Z o o"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:92:72:60:7c:fc:98:2b:78:2a:5d:36:c4:b7:8f:5e:7b"
      cert_thumbprint     = "1ABBDA4B6BF337E98A7AE2C025F18499304E2BEB"
      cert_valid_from     = "2020-11-12"
      cert_valid_to       = "2021-11-12"

      country             = "PL"
      state               = "???"
      locality            = "Kraków"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:92:72:60:7c:fc:98:2b:78:2a:5d:36:c4:b7:8f:5e:7b"
      )
}
