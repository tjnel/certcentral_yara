import "pe"

rule MAL_Compromised_Cert_RaccoonStealer_Sectigo_7709D2DF39E9A4F7DB2F3CBC29B49743 {
   meta:
      description         = "Detects RaccoonStealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-10-03"
      version             = "1.0"

      hash                = "e8002fbc4bd5e57fd317fb99e3bb2bc8965e94761e37757aed51f3f21486c0ad"
      malware             = "RaccoonStealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Grina LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "77:09:d2:df:39:e9:a4:f7:db:2f:3c:bc:29:b4:97:43"
      cert_thumbprint     = "5430CC38C8218F3CF754A01D5A5612C26404068E"
      cert_valid_from     = "2020-10-03"
      cert_valid_to       = "2021-10-03"

      country             = "RU"
      state               = "???"
      locality            = "Novosibirsk"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "77:09:d2:df:39:e9:a4:f7:db:2f:3c:bc:29:b4:97:43"
      )
}
