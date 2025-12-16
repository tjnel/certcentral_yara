import "pe"

rule MAL_Compromised_Cert_QuakBot_Sectigo_45245EEF53FCF38169C715CF68F44452 {
   meta:
      description         = "Detects QuakBot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-12-20"
      version             = "1.0"

      hash                = "baad4165318587463cd3bd68857e6ebb43b8b184a8e9af133da1c786a0dd7a21"
      malware             = "QuakBot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "PAPER AND CORE SUPPLIES LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "45:24:5e:ef:53:fc:f3:81:69:c7:15:cf:68:f4:44:52"
      cert_thumbprint     = "448FCB70D90CBFD544E96149B85DC6364A3DB274"
      cert_valid_from     = "2021-12-20"
      cert_valid_to       = "2022-12-20"

      country             = "GB"
      state               = "London"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "45:24:5e:ef:53:fc:f3:81:69:c7:15:cf:68:f4:44:52"
      )
}
