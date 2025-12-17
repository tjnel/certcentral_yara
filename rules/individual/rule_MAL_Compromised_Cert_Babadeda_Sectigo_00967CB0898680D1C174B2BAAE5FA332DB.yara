import "pe"

rule MAL_Compromised_Cert_Babadeda_Sectigo_00967CB0898680D1C174B2BAAE5FA332DB {
   meta:
      description         = "Detects Babadeda with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-08-11"
      version             = "1.0"

      hash                = "46e406fe4b978a36a98282420eed3c40ddb1c3818575015f9980597e770513d3"
      malware             = "Babadeda"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "James Caulfield"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:96:7c:b0:89:86:80:d1:c1:74:b2:ba:ae:5f:a3:32:db"
      cert_thumbprint     = "66D72ED7487F47C4BB1A329F7F748A7714B06F2F"
      cert_valid_from     = "2020-08-11"
      cert_valid_to       = "2023-08-11"

      country             = "US"
      state               = "Illinois"
      locality            = "Aurora"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:96:7c:b0:89:86:80:d1:c1:74:b2:ba:ae:5f:a3:32:db"
      )
}
