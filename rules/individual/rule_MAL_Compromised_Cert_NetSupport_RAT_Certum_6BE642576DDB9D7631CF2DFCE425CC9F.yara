import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_Certum_6BE642576DDB9D7631CF2DFCE425CC9F {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-12-01"
      version             = "1.0"

      hash                = "672eebccfb00a9a4cc11fec4232eff3c87f7870d1cef4c647d364801cab814ca"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Cloud Estates London Limited"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing CA SHA2"
      cert_serial         = "6b:e6:42:57:6d:db:9d:76:31:cf:2d:fc:e4:25:cc:9f"
      cert_thumbprint     = "56D79CEB82432BD6E4EBE56779049DE806A2D3B4"
      cert_valid_from     = "2020-12-01"
      cert_valid_to       = "2021-12-01"

      country             = "GB"
      state               = "London"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "10476674"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing CA SHA2" and
         sig.serial == "6b:e6:42:57:6d:db:9d:76:31:cf:2d:fc:e4:25:cc:9f"
      )
}
