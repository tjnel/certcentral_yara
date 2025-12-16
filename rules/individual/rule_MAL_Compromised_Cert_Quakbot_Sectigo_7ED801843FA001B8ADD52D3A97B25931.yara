import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_7ED801843FA001B8ADD52D3A97B25931 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-02-26"
      version             = "1.0"

      hash                = "d148d0eee0b33861cc58801464a1c04c4b61aaf87be8b2fbc027d8fd1ce8b9a6"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "AM El-Teknik ApS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "7e:d8:01:84:3f:a0:01:b8:ad:d5:2d:3a:97:b2:59:31"
      cert_thumbprint     = "4EE1539C1455F0070D8D04820FB814F8794F84DF"
      cert_valid_from     = "2021-02-26"
      cert_valid_to       = "2022-02-26"

      country             = "DK"
      state               = "Hovedstaden"
      locality            = "Ølstykke"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "7e:d8:01:84:3f:a0:01:b8:ad:d5:2d:3a:97:b2:59:31"
      )
}
