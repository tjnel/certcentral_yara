import "pe"

rule MAL_Compromised_Cert_RemoteManipulator_Sectigo_7DDD3796A427B42F2E52D7C7AF0CA54F {
   meta:
      description         = "Detects RemoteManipulator with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-02-10"
      version             = "1.0"

      hash                = "ddca8f9d05aa07e903b71aa9823252962f91d0a192b79e346f8a51f39fb9212d"
      malware             = "RemoteManipulator"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "OOO Fobos"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "7d:dd:37:96:a4:27:b4:2f:2e:52:d7:c7:af:0c:a5:4f"
      cert_thumbprint     = "B5CD5A485DEE4A82F34C98B3F108579E8501FDEA"
      cert_valid_from     = "2021-02-10"
      cert_valid_to       = "2022-02-10"

      country             = "RU"
      state               = "???"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "7d:dd:37:96:a4:27:b4:2f:2e:52:d7:c7:af:0c:a5:4f"
      )
}
