import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00DA156922F4760E0C5F5BCF79812A27E1 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-04-05"
      version             = "1.0"

      hash                = "2b9861436d994bee6a332cbaf71a9fd6f157089062f414207c9effe84bf556e5"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "DRINK AND BUBBLE LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:da:15:69:22:f4:76:0e:0c:5f:5b:cf:79:81:2a:27:e1"
      cert_thumbprint     = "3E4EA5E17FEA0603E82D9FE1376D739B827C4E5B"
      cert_valid_from     = "2022-04-05"
      cert_valid_to       = "2023-04-05"

      country             = "GB"
      state               = "London"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:da:15:69:22:f4:76:0e:0c:5f:5b:cf:79:81:2a:27:e1"
      )
}
