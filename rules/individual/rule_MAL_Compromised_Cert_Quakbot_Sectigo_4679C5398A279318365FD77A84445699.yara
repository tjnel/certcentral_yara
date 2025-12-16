import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_4679C5398A279318365FD77A84445699 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-02-03"
      version             = "1.0"

      hash                = "964b4ec11e60e4a5f7464b8ec4510f6f514e7e49185da9f445e07724536febd0"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "HURT GROUP HOLDINGS LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "46:79:c5:39:8a:27:93:18:36:5f:d7:7a:84:44:56:99"
      cert_thumbprint     = "0962F0A080BC1AB38AA39730D38AF2603DC65BD4"
      cert_valid_from     = "2022-02-03"
      cert_valid_to       = "2023-02-03"

      country             = "GB"
      state               = "Lancashire"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "46:79:c5:39:8a:27:93:18:36:5f:d7:7a:84:44:56:99"
      )
}
