import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00B2F9C693A2E6634565F63C79B01DD8F8 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-05-03"
      version             = "1.0"

      hash                = "e3bf20fa69644c0ca34c600feb3c43f70a1d51408534d1167825a2178a7b7073"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "PHL E STATE ApS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:b2:f9:c6:93:a2:e6:63:45:65:f6:3c:79:b0:1d:d8:f8"
      cert_thumbprint     = "7F6DB1E8EFE0831E81A5994DD74158875D0D8268"
      cert_valid_from     = "2021-05-03"
      cert_valid_to       = "2022-05-03"

      country             = "DK"
      state               = "Hovedstaden"
      locality            = "Gentofte"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:b2:f9:c6:93:a2:e6:63:45:65:f6:3c:79:b0:1d:d8:f8"
      )
}
