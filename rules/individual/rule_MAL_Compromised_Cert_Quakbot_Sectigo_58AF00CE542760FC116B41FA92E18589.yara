import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_58AF00CE542760FC116B41FA92E18589 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-06-10"
      version             = "1.0"

      hash                = "78bc13074087f93fcc8f11ae013995f9a366b6943330c3d02f0b50c4ae96c8a7"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "DICKIE MUSDALE WINDFARM LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "58:af:00:ce:54:27:60:fc:11:6b:41:fa:92:e1:85:89"
      cert_thumbprint     = "AE5E59B981901B69380AC47D0FF499D1BA0AFFC2"
      cert_valid_from     = "2022-06-10"
      cert_valid_to       = "2023-06-10"

      country             = "GB"
      state               = "Scotland"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "58:af:00:ce:54:27:60:fc:11:6b:41:fa:92:e1:85:89"
      )
}
