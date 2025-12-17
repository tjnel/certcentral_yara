import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_2782171DABF21DBB7C0A155C38BC1FFB {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-06-17"
      version             = "1.0"

      hash                = "0f069b41245d76dd228b512cc1f3bac12e656bcd1b5415c30048bfdba2f5e208"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Bauder Ltd"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "27:82:17:1d:ab:f2:1d:bb:7c:0a:15:5c:38:bc:1f:fb"
      cert_thumbprint     = "3bb2dd50469f7023a23b176ea6edd1d8ec27bb9b6a77a7031a05c11611b55db4"
      cert_valid_from     = "2021-06-17"
      cert_valid_to       = "2022-06-17"

      country             = "GB"
      state               = "Norfolk"
      locality            = "Norwich"
      email               = "???"
      rdn_serial_number   = "01466215"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "27:82:17:1d:ab:f2:1d:bb:7c:0a:15:5c:38:bc:1f:fb"
      )
}
