import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_26F855A25890B749578F13E4B9459768 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-02-21"
      version             = "1.0"

      hash                = "866343b3294e723c5ba44a197dd24e180471ca3f5b811281b16087855b369c16"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Boo’s Q & Sweets Corporation"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "26:f8:55:a2:58:90:b7:49:57:8f:13:e4:b9:45:97:68"
      cert_thumbprint     = "20553AC4E2BBDE9BAC6065884BFA05BA6EF789C0"
      cert_valid_from     = "2022-02-21"
      cert_valid_to       = "2023-02-21"

      country             = "CA"
      state               = "Ontario"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "26:f8:55:a2:58:90:b7:49:57:8f:13:e4:b9:45:97:68"
      )
}
