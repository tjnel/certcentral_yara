import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_TrustOcean_066276AF2F2C7E246D3B1CAB1B4AA42E {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (TrustOcean)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-25"
      version             = "1.0"

      hash                = "222c327eef40050baf9e05f80d39f53bf7955bd84bf212887405a665060c369f"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "IQ Trade ApS"
      cert_issuer_short   = "TrustOcean"
      cert_issuer         = "TrustOcean Organization Software Vendor CA"
      cert_serial         = "06:62:76:af:2f:2c:7e:24:6d:3b:1c:ab:1b:4a:a4:2e"
      cert_thumbprint     = "DEE5CA4BE94A8737C85BBEE27BD9D81B235FB700"
      cert_valid_from     = "2021-03-25"
      cert_valid_to       = "2022-03-25"

      country             = "DK"
      state               = "???"
      locality            = "Rødovre"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "TrustOcean Organization Software Vendor CA" and
         sig.serial == "06:62:76:af:2f:2c:7e:24:6d:3b:1c:ab:1b:4a:a4:2e"
      )
}
