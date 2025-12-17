import "pe"

rule MAL_Compromised_Cert_TA505_Sectigo_00F454F2FDC800B3454059D8889BD73D67 {
   meta:
      description         = "Detects TA505 with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-05-25"
      version             = "1.0"

      hash                = "e58b80e4738dc03f5aa82d3a40a6d2ace0d7c7cfd651f1dd10df76d43d8c0eb3"
      malware             = "TA505"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "BEAUTY CORP SRL"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:f4:54:f2:fd:c8:00:b3:45:40:59:d8:88:9b:d7:3d:67"
      cert_thumbprint     = "2B560FABC34E0DB81DAE1443B1C4929EEF820266"
      cert_valid_from     = "2021-05-25"
      cert_valid_to       = "2024-05-24"

      country             = "RO"
      state               = "???"
      locality            = "Botosani"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:f4:54:f2:fd:c8:00:b3:45:40:59:d8:88:9b:d7:3d:67"
      )
}
