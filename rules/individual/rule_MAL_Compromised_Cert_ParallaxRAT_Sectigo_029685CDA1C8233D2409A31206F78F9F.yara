import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_029685CDA1C8233D2409A31206F78F9F {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-02-04"
      version             = "1.0"

      hash                = "4737b939774fa43ffaec93dcee6112b2c3372bcd9910ecd2969cb8dc75ef4857"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "KOTO TRADE, družba za posredovanje, d.o.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "02:96:85:cd:a1:c8:23:3d:24:09:a3:12:06:f7:8f:9f"
      cert_thumbprint     = "86574B0EF7FBCE15F208BF801866F34C664CF7CE"
      cert_valid_from     = "2021-02-04"
      cert_valid_to       = "2022-02-04"

      country             = "SI"
      state               = "???"
      locality            = "Ljubljana"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "02:96:85:cd:a1:c8:23:3d:24:09:a3:12:06:f7:8f:9f"
      )
}
