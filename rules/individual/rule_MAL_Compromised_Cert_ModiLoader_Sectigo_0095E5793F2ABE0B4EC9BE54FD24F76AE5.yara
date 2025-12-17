import "pe"

rule MAL_Compromised_Cert_ModiLoader_Sectigo_0095E5793F2ABE0B4EC9BE54FD24F76AE5 {
   meta:
      description         = "Detects ModiLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-09-16"
      version             = "1.0"

      hash                = "56007af3c6b00548660560601efe9e3ea1fbec553562dd7436fe85673ed7a0c8"
      malware             = "ModiLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Kommservice LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:95:e5:79:3f:2a:be:0b:4e:c9:be:54:fd:24:f7:6a:e5"
      cert_thumbprint     = "6ACDFEE2A1AB425B7927D0FFE6AFC38C794F1240"
      cert_valid_from     = "2020-09-16"
      cert_valid_to       = "2021-09-16"

      country             = "RU"
      state               = "???"
      locality            = "Moskva"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:95:e5:79:3f:2a:be:0b:4e:c9:be:54:fd:24:f7:6a:e5"
      )
}
