import "pe"

rule MAL_Compromised_Cert_BazaLoader_Sectigo_5A9D897077A22AFE7AD4C4A01DF6C418 {
   meta:
      description         = "Detects BazaLoader with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-10-07"
      version             = "1.0"

      hash                = "e888f380a5cee9d9db4c47c84a4c78bcc2affc2fc3099038eb7e2afc66eb7863"
      malware             = "BazaLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Klarens LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "5a:9d:89:70:77:a2:2a:fe:7a:d4:c4:a0:1d:f6:c4:18"
      cert_thumbprint     = "23D00CD0BB9E7F15E2373438D87BB216A6B6132F"
      cert_valid_from     = "2020-10-07"
      cert_valid_to       = "2021-10-07"

      country             = "RU"
      state               = "???"
      locality            = "Bratsk"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "5a:9d:89:70:77:a2:2a:fe:7a:d4:c4:a0:1d:f6:c4:18"
      )
}
