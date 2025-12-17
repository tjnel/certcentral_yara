import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00E38259CF24CC702CE441B683AD578911 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-08-13"
      version             = "1.0"

      hash                = "f953b103ae09065e639890aa4e133f54ac9a2a5f5eb519d970b2b8d40d251626"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Akhirah Technologies Inc."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:e3:82:59:cf:24:cc:70:2c:e4:41:b6:83:ad:57:89:11"
      cert_thumbprint     = "528F7B649E2600B5F5672233611A9319858B9A9F"
      cert_valid_from     = "2020-08-13"
      cert_valid_to       = "2021-08-13"

      country             = "CA"
      state               = "Ontario"
      locality            = "Etobicoke"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:e3:82:59:cf:24:cc:70:2c:e4:41:b6:83:ad:57:89:11"
      )
}
