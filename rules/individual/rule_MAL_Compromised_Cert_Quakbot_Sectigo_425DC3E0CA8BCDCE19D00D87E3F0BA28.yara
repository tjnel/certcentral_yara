import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_425DC3E0CA8BCDCE19D00D87E3F0BA28 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-05-25"
      version             = "1.0"

      hash                = "29ab0dd1ecd81ef53162bc8d991b18113eac17f876cac17ffc301e589030f9a2"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Protover LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "42:5d:c3:e0:ca:8b:cd:ce:19:d0:0d:87:e3:f0:ba:28"
      cert_thumbprint     = "C58BC4370FA01D9A7772FA8C0E7C4C6C99B90561"
      cert_valid_from     = "2021-05-25"
      cert_valid_to       = "2022-05-25"

      country             = "RU"
      state               = "???"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "42:5d:c3:e0:ca:8b:cd:ce:19:d0:0d:87:e3:f0:ba:28"
      )
}
