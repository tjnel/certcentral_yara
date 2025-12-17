import "pe"

rule MAL_Compromised_Cert_Sodinokibi_Sectigo_08D4DC90047B8470CCAF3924DFBD8B5F {
   meta:
      description         = "Detects Sodinokibi with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-04-23"
      version             = "1.0"

      hash                = "0496ca57e387b10dfdac809de8a4e039f68e8d66535d5d19ec76d39f7d0a4402"
      malware             = "Sodinokibi"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "OOO Dibies"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "08:d4:dc:90:04:7b:84:70:cc:af:39:24:df:bd:8b:5f"
      cert_thumbprint     = "FE5AEB5935504D636E95096DDEA1D724CB2C8123"
      cert_valid_from     = "2021-04-23"
      cert_valid_to       = "2022-04-23"

      country             = "RU"
      state               = "???"
      locality            = "St. Petersburg"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "08:d4:dc:90:04:7b:84:70:cc:af:39:24:df:bd:8b:5f"
      )
}
