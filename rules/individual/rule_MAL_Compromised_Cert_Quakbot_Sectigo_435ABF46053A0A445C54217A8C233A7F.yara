import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_435ABF46053A0A445C54217A8C233A7F {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-29"
      version             = "1.0"

      hash                = "ae940943dc46aa505baf564660c241d7ac92a0018b663142ba08296f6d129af2"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "OOO Kodemika"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "43:5a:bf:46:05:3a:0a:44:5c:54:21:7a:8c:23:3a:7f"
      cert_thumbprint     = "94D6E69564868A44FEB430D4166A71C251F4AC0D"
      cert_valid_from     = "2021-03-29"
      cert_valid_to       = "2022-03-29"

      country             = "RU"
      state               = "???"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "43:5a:bf:46:05:3a:0a:44:5c:54:21:7a:8c:23:3a:7f"
      )
}
