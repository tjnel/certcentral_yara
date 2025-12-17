import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00FF52EB011BB748FEE75153CBE1E50DD6 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-03-16"
      version             = "1.0"

      hash                = "62653335118bb647653455b6aba600123b00a26e2b1fb74ad422b66abba60cfe"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "TASK ANNA LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:ff:52:eb:01:1b:b7:48:fe:e7:51:53:cb:e1:e5:0d:d6"
      cert_thumbprint     = "5158D965A6FFABA73FBB2EDE0E540100B8FD15CC"
      cert_valid_from     = "2022-03-16"
      cert_valid_to       = "2023-03-16"

      country             = "GB"
      state               = "Northamptonshire"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:ff:52:eb:01:1b:b7:48:fe:e7:51:53:cb:e1:e5:0d:d6"
      )
}
