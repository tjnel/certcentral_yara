import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_35590EBE4A02DC23317D8CE47A947A9B {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-10-09"
      version             = "1.0"

      hash                = "fab5aa283fc3a246f79d64cd53a2a6ac62aa0a34d86c2f637d766adb16574a99"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "OOO Largos"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "35:59:0e:be:4a:02:dc:23:31:7d:8c:e4:7a:94:7a:9b"
      cert_thumbprint     = "3B454479F75CEE023D1C92950DD40D9AF965575C"
      cert_valid_from     = "2020-10-09"
      cert_valid_to       = "2021-10-09"

      country             = "RU"
      state               = "???"
      locality            = "Novosibirsk"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "35:59:0e:be:4a:02:dc:23:31:7d:8c:e4:7a:94:7a:9b"
      )
}
