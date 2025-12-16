import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00AFE8FEE94B41422E01E4897BCD52D0A4 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-30"
      version             = "1.0"

      hash                = "253b5a915f1d7e14804228c862f39df4f8b2a7e7f96d94a863069c1c4d87e4e6"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "TLGM ApS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:af:e8:fe:e9:4b:41:42:2e:01:e4:89:7b:cd:52:d0:a4"
      cert_thumbprint     = "6E0E838F5F5194DC08CC0D750E76B2DA3060265C"
      cert_valid_from     = "2021-03-30"
      cert_valid_to       = "2022-03-30"

      country             = "DK"
      state               = "???"
      locality            = "Allerød"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:af:e8:fe:e9:4b:41:42:2e:01:e4:89:7b:cd:52:d0:a4"
      )
}
