import "pe"

rule MAL_Compromised_Cert_Nemty_Sectigo_00FC7065ABF8303FB472B8AF85918F5C24 {
   meta:
      description         = "Detects Nemty with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-11-03"
      version             = "1.0"

      hash                = "006c9ba4ca0218e7bd2c7c21653497d3215bbeefbc1f5c2781549b306bab8e5e"
      malware             = "Nemty"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "DIG IN VISION SP Z O O"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:fc:70:65:ab:f8:30:3f:b4:72:b8:af:85:91:8f:5c:24"
      cert_thumbprint     = "B61A6607154D27D64DE35E7529CB853DCB47F51F"
      cert_valid_from     = "2020-11-03"
      cert_valid_to       = "2021-11-03"

      country             = "PL"
      state               = "???"
      locality            = "Wrocław"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:fc:70:65:ab:f8:30:3f:b4:72:b8:af:85:91:8f:5c:24"
      )
}
