import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_1FFC9825644CAF5B1F521780C5C7F42C {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-12"
      version             = "1.0"

      hash                = "378a6fdf9d2629f912926cdee7dbe401675d31dda23fa6a0b5a150db80e62739"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "ACTIVUS LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "1f:fc:98:25:64:4c:af:5b:1f:52:17:80:c5:c7:f4:2c"
      cert_thumbprint     = "4E7E022C7BB6BD90A75674A67F82E839D54A0A5E"
      cert_valid_from     = "2021-03-12"
      cert_valid_to       = "2022-03-12"

      country             = "NZ"
      state               = "???"
      locality            = "Christchurch"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "1f:fc:98:25:64:4c:af:5b:1f:52:17:80:c5:c7:f4:2c"
      )
}
