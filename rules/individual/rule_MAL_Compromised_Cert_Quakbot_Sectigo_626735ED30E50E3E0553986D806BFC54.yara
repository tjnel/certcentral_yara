import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_626735ED30E50E3E0553986D806BFC54 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-10-26"
      version             = "1.0"

      hash                = "085f0f3f25b1328d153a7c56125e1d8a4d43bc882fe3f250d742ea5247850c02"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "FISH ACCOUNTING & TRANSLATING LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "62:67:35:ed:30:e5:0e:3e:05:53:98:6d:80:6b:fc:54"
      cert_thumbprint     = "AAD723780CD440026A6CA0AA1E9D13D09F877E8F"
      cert_valid_from     = "2022-10-26"
      cert_valid_to       = "2023-10-26"

      country             = "GB"
      state               = "Cambridgeshire"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "62:67:35:ed:30:e5:0e:3e:05:53:98:6d:80:6b:fc:54"
      )
}
