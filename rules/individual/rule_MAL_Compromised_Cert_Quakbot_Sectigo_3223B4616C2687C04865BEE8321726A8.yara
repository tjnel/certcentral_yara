import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_3223B4616C2687C04865BEE8321726A8 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-09-29"
      version             = "1.0"

      hash                = "8584e035ae371ae08206bc56eaffdb6ebb0284adfdd3612f6ae40d07676d5f08"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "FORTUNE STAR TRADING, INC."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "32:23:b4:61:6c:26:87:c0:48:65:be:e8:32:17:26:a8"
      cert_thumbprint     = "07EB627B760C866485296D97AD41118C023D9B0C"
      cert_valid_from     = "2020-09-29"
      cert_valid_to       = "2021-09-29"

      country             = "US"
      state               = "California"
      locality            = "SAN FRANCISCO"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "32:23:b4:61:6c:26:87:c0:48:65:be:e8:32:17:26:a8"
      )
}
