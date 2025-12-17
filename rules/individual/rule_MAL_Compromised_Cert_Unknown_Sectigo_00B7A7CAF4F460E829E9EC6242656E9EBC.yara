import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_00B7A7CAF4F460E829E9EC6242656E9EBC {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-14"
      version             = "1.0"

      hash                = "cd7bc397ef12fa884dd717066ab377165bbb7a335f8909ebf4d61328b1d77e6c"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shanghai Yuesong Information Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:b7:a7:ca:f4:f4:60:e8:29:e9:ec:62:42:65:6e:9e:bc"
      cert_thumbprint     = "64041D7F9952E102B669690C61EFD12F77E8E497"
      cert_valid_from     = "2024-05-14"
      cert_valid_to       = "2025-05-14"

      country             = "CN"
      state               = "Shanghai Shi"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:b7:a7:ca:f4:f4:60:e8:29:e9:ec:62:42:65:6e:9e:bc"
      )
}
