import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_690910DC89D7857C3500FB74BED2B08D {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-08-13"
      version             = "1.0"

      hash                = "fe1fe8c9671f6b23f16c52d3a726ba99f00e2559e7991c4e67d88b7cf945da9d"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "OLIMP STROI, OOO"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "69:09:10:dc:89:d7:85:7c:35:00:fb:74:be:d2:b0:8d"
      cert_thumbprint     = "030C98A029F7CC4B460187AE954E304055EF2C6D"
      cert_valid_from     = "2020-08-13"
      cert_valid_to       = "2021-08-13"

      country             = "RU"
      state               = "Saratovskaya oblast"
      locality            = "Saratov"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "69:09:10:dc:89:d7:85:7c:35:00:fb:74:be:d2:b0:8d"
      )
}
