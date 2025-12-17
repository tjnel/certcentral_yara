import "pe"

rule MAL_Compromised_Cert_TA505_Sectigo_00B8164F7143E1A313003AB0C834562F1F {
   meta:
      description         = "Detects TA505 with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-08-25"
      version             = "1.0"

      hash                = "c79957ca77f6355fb02b9a0d9d2a4c86bca3d6fd53afbf03d6e981da5bb43689"
      malware             = "TA505"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ekitai Data Inc."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:b8:16:4f:71:43:e1:a3:13:00:3a:b0:c8:34:56:2f:1f"
      cert_thumbprint     = "8BEBDCDD636C7172C3AA79B0F1F31311C61A3232"
      cert_valid_from     = "2020-08-25"
      cert_valid_to       = "2021-08-25"

      country             = "CA"
      state               = "Ontario"
      locality            = "Thornhill"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:b8:16:4f:71:43:e1:a3:13:00:3a:b0:c8:34:56:2f:1f"
      )
}
