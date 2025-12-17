import "pe"

rule MAL_Compromised_Cert_Softwarecloud_Microsoft_330002AF381AAD80145EB45EE000000002AF38 {
   meta:
      description         = "Detects Softwarecloud with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-01"
      version             = "1.0"

      hash                = "8bbef77fe39bd8c943243e13d92f30e1b65f01b57902473af53a5621bd7df029"
      malware             = "Softwarecloud"
      malware_type        = "Unknown"
      malware_notes       = "This malware is part of a campaign of inauthentic software. More research is likely needed: https://x.com/andrewdanis/status/1919585650413629680?s=20"

      signer              = "El Web Development Ltd"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:02:af:38:1a:ad:80:14:5e:b4:5e:e0:00:00:00:02:af:38"
      cert_thumbprint     = "ABCF0879BFB55D10A5620A39B15A219FD937B6C1"
      cert_valid_from     = "2025-05-01"
      cert_valid_to       = "2025-05-04"

      country             = "GB"
      state               = "???"
      locality            = "Birmingham"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:02:af:38:1a:ad:80:14:5e:b4:5e:e0:00:00:00:02:af:38"
      )
}
