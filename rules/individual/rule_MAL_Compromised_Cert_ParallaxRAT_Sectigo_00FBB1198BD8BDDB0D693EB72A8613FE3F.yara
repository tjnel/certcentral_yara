import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_00FBB1198BD8BDDB0D693EB72A8613FE3F {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-05-03"
      version             = "1.0"

      hash                = "abba8d0990bb52ecc9c282ca8e98e83076fbd5d86afe2efecdbc236a5c610de8"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "Trade Hunters, s. r. o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:fb:b1:19:8b:d8:bd:db:0d:69:3e:b7:2a:86:13:fe:3f"
      cert_thumbprint     = "8D9EFDCE4F0D50387D8A6FD6C349DB593A00FB20"
      cert_valid_from     = "2021-05-03"
      cert_valid_to       = "2022-05-03"

      country             = "SK"
      state               = "Bratislavský kraj"
      locality            = "mestská časť Rača"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:fb:b1:19:8b:d8:bd:db:0d:69:3e:b7:2a:86:13:fe:3f"
      )
}
