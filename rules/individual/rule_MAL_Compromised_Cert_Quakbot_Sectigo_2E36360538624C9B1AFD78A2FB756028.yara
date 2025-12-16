import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_2E36360538624C9B1AFD78A2FB756028 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-15"
      version             = "1.0"

      hash                = "ead37db279d439a8b30916b254590b21fe9ed268447bafd2fbc8e693e8ba7200"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Ts Trade ApS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "2e:36:36:05:38:62:4c:9b:1a:fd:78:a2:fb:75:60:28"
      cert_thumbprint     = "CE0A151E91751F047A6A77D327E52489AF380B1D"
      cert_valid_from     = "2021-03-15"
      cert_valid_to       = "2022-03-15"

      country             = "DK"
      state               = "Hovedstaden"
      locality            = "Charlottenlund"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "2e:36:36:05:38:62:4c:9b:1a:fd:78:a2:fb:75:60:28"
      )
}
