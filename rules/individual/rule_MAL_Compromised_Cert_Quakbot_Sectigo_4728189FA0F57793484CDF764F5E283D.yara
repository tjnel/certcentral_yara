import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_4728189FA0F57793484CDF764F5E283D {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-03-15"
      version             = "1.0"

      hash                = "d5ef3d005f494f728076a6e0fe22a9160ac4fa584f4956582cbe77b499b586de"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Power Save Systems s.r.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "47:28:18:9f:a0:f5:77:93:48:4c:df:76:4f:5e:28:3d"
      cert_thumbprint     = "2BEE3F716B80273DB9639376A296CF19CDBA0F1A"
      cert_valid_from     = "2022-03-15"
      cert_valid_to       = "2023-03-15"

      country             = "CZ"
      state               = "Plzeňský kraj"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "47:28:18:9f:a0:f5:77:93:48:4c:df:76:4f:5e:28:3d"
      )
}
