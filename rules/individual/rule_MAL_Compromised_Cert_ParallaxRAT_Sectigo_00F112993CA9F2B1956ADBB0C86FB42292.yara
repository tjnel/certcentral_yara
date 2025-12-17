import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_00F112993CA9F2B1956ADBB0C86FB42292 {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-05-19"
      version             = "1.0"

      hash                = "d8eb5792d969c21c364da69eca1322ab5f63e0a39b0e542bad4ee95be873c296"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "Key 4 Solutions, s. r. o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:f1:12:99:3c:a9:f2:b1:95:6a:db:b0:c8:6f:b4:22:92"
      cert_thumbprint     = "82D94E43B13C84DCFAD0AB35A73077F61524336E"
      cert_valid_from     = "2021-05-19"
      cert_valid_to       = "2022-05-19"

      country             = "SK"
      state               = "???"
      locality            = "Bratislava - mestská časť Ružinov"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:f1:12:99:3c:a9:f2:b1:95:6a:db:b0:c8:6f:b4:22:92"
      )
}
