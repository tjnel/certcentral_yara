import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_38989EC61ECDB7391FF5647F7D58AD18 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-02-12"
      version             = "1.0"

      hash                = "ec9352eeb82834a128bd306eddc085b5138083a4ce1e98d847fd936a309b52cb"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "RotA Games ApS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "38:98:9e:c6:1e:cd:b7:39:1f:f5:64:7f:7d:58:ad:18"
      cert_thumbprint     = "71E74A735C72D220AA45E9F1B83F0B867F2DA166"
      cert_valid_from     = "2021-02-12"
      cert_valid_to       = "2022-02-12"

      country             = "DK"
      state               = "???"
      locality            = "Aalborg"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "38:98:9e:c6:1e:cd:b7:39:1f:f5:64:7f:7d:58:ad:18"
      )
}
