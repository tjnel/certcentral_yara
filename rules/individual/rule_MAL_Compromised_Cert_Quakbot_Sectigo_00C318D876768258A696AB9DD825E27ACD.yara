import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00C318D876768258A696AB9DD825E27ACD {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-08"
      version             = "1.0"

      hash                = "4be7aad46de1042ea916b9e6ef6f18fcb56b40e768b94b733b70ca2995866cc6"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "OOO Genezis"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:c3:18:d8:76:76:82:58:a6:96:ab:9d:d8:25:e2:7a:cd"
      cert_thumbprint     = "4D201ED143905E95834BEC8161225ACDC38A8827"
      cert_valid_from     = "2021-03-08"
      cert_valid_to       = "2022-03-08"

      country             = "RU"
      state               = "???"
      locality            = "Ufa"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:c3:18:d8:76:76:82:58:a6:96:ab:9d:d8:25:e2:7a:cd"
      )
}
