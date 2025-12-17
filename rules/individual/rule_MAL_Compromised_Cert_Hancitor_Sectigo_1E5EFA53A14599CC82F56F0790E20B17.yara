import "pe"

rule MAL_Compromised_Cert_Hancitor_Sectigo_1E5EFA53A14599CC82F56F0790E20B17 {
   meta:
      description         = "Detects Hancitor with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-06-09"
      version             = "1.0"

      hash                = "73b8c566d8cdf3200daa0b698b9d32a49b1ea8284a1e6aa6408eb9c9daaacb71"
      malware             = "Hancitor"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Storeks LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "1e:5e:fa:53:a1:45:99:cc:82:f5:6f:07:90:e2:0b:17"
      cert_thumbprint     = "91319E6A55BF0EF68DB8AFB31845AB961356175F"
      cert_valid_from     = "2021-06-09"
      cert_valid_to       = "2022-06-09"

      country             = "RU"
      state               = "???"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "1e:5e:fa:53:a1:45:99:cc:82:f5:6f:07:90:e2:0b:17"
      )
}
