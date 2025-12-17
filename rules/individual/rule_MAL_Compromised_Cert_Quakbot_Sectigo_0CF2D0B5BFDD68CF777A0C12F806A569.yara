import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_0CF2D0B5BFDD68CF777A0C12F806A569 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-01-27"
      version             = "1.0"

      hash                = "f270de517926fb72dbc2e5e5d7335568f426fc524ad07e0ba553619080dbba3c"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "PROTIP d.o.o. - v stečaju"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "0c:f2:d0:b5:bf:dd:68:cf:77:7a:0c:12:f8:06:a5:69"
      cert_thumbprint     = "0C212CDF3D9A46621C19AF5C494FF6BAD25D3190"
      cert_valid_from     = "2021-01-27"
      cert_valid_to       = "2022-01-27"

      country             = "SI"
      state               = "???"
      locality            = "Domžale"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "0c:f2:d0:b5:bf:dd:68:cf:77:7a:0c:12:f8:06:a5:69"
      )
}
