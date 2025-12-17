import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00CA646B4275406DF639CF603756F63D77 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-11-20"
      version             = "1.0"

      hash                = "6fcb5a86e736d4ec02334c9573a3eab21769538b30786cf02c5744ad5336594f"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "SHOECORP LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:ca:64:6b:42:75:40:6d:f6:39:cf:60:37:56:f6:3d:77"
      cert_thumbprint     = "2A68CFAD2D82CAAE48D4DCBB49AA73AAF3FE79DD"
      cert_valid_from     = "2020-11-20"
      cert_valid_to       = "2021-11-20"

      country             = "IE"
      state               = "???"
      locality            = "TIPPERARY"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:ca:64:6b:42:75:40:6d:f6:39:cf:60:37:56:f6:3d:77"
      )
}
