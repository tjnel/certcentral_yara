import "pe"

rule MAL_Compromised_Cert_BumbleBee_Sectigo_65CFD8419D70CE4011D97BC79D18315E {
   meta:
      description         = "Detects BumbleBee with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-07-08"
      version             = "1.0"

      hash                = "35f2ec59313bbe5b78e4b043f06f8961f6f3e77b870544d15ee7cc1fca987d8c"
      malware             = "BumbleBee"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "FACE AESTHETICS LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "65:cf:d8:41:9d:70:ce:40:11:d9:7b:c7:9d:18:31:5e"
      cert_thumbprint     = "0AE02319FD09F729299428D15247D6843C7FBE2D"
      cert_valid_from     = "2022-07-08"
      cert_valid_to       = "2023-07-08"

      country             = "GB"
      state               = "Shropshire"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "65:cf:d8:41:9d:70:ce:40:11:d9:7b:c7:9d:18:31:5e"
      )
}
