import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_Sectigo_2924785FD7990B2D510675176DAE2BED {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-07-14"
      version             = "1.0"

      hash                = "68313d4b45cc908f541dd581d7b9d1e8ccadcbf205714c12c36b58083ada7345"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Neoopt LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "29:24:78:5f:d7:99:0b:2d:51:06:75:17:6d:ae:2b:ed"
      cert_thumbprint     = "71FC852FFCC92F6ED54CF703BB825E084410878C"
      cert_valid_from     = "2020-07-14"
      cert_valid_to       = "2021-07-14"

      country             = "RU"
      state               = "???"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "29:24:78:5f:d7:99:0b:2d:51:06:75:17:6d:ae:2b:ed"
      )
}
