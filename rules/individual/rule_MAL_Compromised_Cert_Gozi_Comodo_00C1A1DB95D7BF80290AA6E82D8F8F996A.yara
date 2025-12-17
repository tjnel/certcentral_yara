import "pe"

rule MAL_Compromised_Cert_Gozi_Comodo_00C1A1DB95D7BF80290AA6E82D8F8F996A {
   meta:
      description         = "Detects Gozi with compromised cert (Comodo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-10"
      version             = "1.0"

      hash                = "8f6b3ca7b7afd249f3fc68f7ff2ce5ca5a206c2a1d123b5ac3aa28bf7f1eabd8"
      malware             = "Gozi"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Software Two Pty Ltd"
      cert_issuer_short   = "Comodo"
      cert_issuer         = "COMODO RSA Extended Validation Code Signing CA"
      cert_serial         = "00:c1:a1:db:95:d7:bf:80:29:0a:a6:e8:2d:8f:8f:99:6a"
      cert_thumbprint     = "C1313E87F7D9586016A32F6EDFCA281D1A3D2D29"
      cert_valid_from     = "2021-03-10"
      cert_valid_to       = "2022-03-10"

      country             = "AU"
      state               = "New South Wales"
      locality            = "Newtown"
      email               = "???"
      rdn_serial_number   = "86 609 945 191"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "COMODO RSA Extended Validation Code Signing CA" and
         sig.serial == "00:c1:a1:db:95:d7:bf:80:29:0a:a6:e8:2d:8f:8f:99:6a"
      )
}
