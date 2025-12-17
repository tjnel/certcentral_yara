import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_1AE3C4ECCECDA2127D43BE390A850DDA {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-05"
      version             = "1.0"

      hash                = "5e840de448a948691f5dcb9699a771e9b0cff4c87a279070aa049eb336afbc9f"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "PARTYNET LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "1a:e3:c4:ec:ce:cd:a2:12:7d:43:be:39:0a:85:0d:da"
      cert_thumbprint     = "61E86F40C4DDBC3B0EDAB66909E061E3B9EDE966"
      cert_valid_from     = "2021-03-05"
      cert_valid_to       = "2022-03-05"

      country             = "IE"
      state               = "???"
      locality            = "Limerick"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "1a:e3:c4:ec:ce:cd:a2:12:7d:43:be:39:0a:85:0d:da"
      )
}
