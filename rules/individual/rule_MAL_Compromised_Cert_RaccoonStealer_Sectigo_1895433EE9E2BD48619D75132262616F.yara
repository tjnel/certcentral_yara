import "pe"

rule MAL_Compromised_Cert_RaccoonStealer_Sectigo_1895433EE9E2BD48619D75132262616F {
   meta:
      description         = "Detects RaccoonStealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-23"
      version             = "1.0"

      hash                = "65482dad9fc3afdae3eadc30dcc55ab9407f93b0d63a2d3e62156f3c104dc22c"
      malware             = "RaccoonStealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Evetrans Ltd"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "18:95:43:3e:e9:e2:bd:48:61:9d:75:13:22:62:61:6f"
      cert_thumbprint     = "69D18725C64C50D58598BD255C26E225EF227D14"
      cert_valid_from     = "2021-03-23"
      cert_valid_to       = "2022-03-23"

      country             = "GB"
      state               = "West Midlands"
      locality            = "Birmingham"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "18:95:43:3e:e9:e2:bd:48:61:9d:75:13:22:62:61:6f"
      )
}
