import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_7156EC47EF01AB8359EF4304E5AF1A05 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-08-14"
      version             = "1.0"

      hash                = "5aef62812d4c85ceff8b7242d7903482754f0f0bd49712f1a9746bd07a99cb72"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "BOREC, OOO"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "71:56:ec:47:ef:01:ab:83:59:ef:43:04:e5:af:1a:05"
      cert_thumbprint     = "6AFA5449C14C28F8F0A53CF49113EE895A2899F2"
      cert_valid_from     = "2020-08-14"
      cert_valid_to       = "2021-08-14"

      country             = "RU"
      state               = "Primorskiy kray"
      locality            = "Vladivostok"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "71:56:ec:47:ef:01:ab:83:59:ef:43:04:e5:af:1a:05"
      )
}
