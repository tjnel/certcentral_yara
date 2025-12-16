import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_00BFCEA72A7A44662E74E77163BD89C2AA {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-07-27"
      version             = "1.0"

      hash                = "389c556e30252966f34f1bc23348e182af2c0883771f9c8abe299a8ba54b1f6a"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "Special Floors ApS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:bf:ce:a7:2a:7a:44:66:2e:74:e7:71:63:bd:89:c2:aa"
      cert_thumbprint     = "D60AB44BE669AE7F22FA5B05FDA65AB30B9ED61A"
      cert_valid_from     = "2021-07-27"
      cert_valid_to       = "2022-07-27"

      country             = "DK"
      state               = "Hovedstaden"
      locality            = "København SV"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:bf:ce:a7:2a:7a:44:66:2e:74:e7:71:63:bd:89:c2:aa"
      )
}
