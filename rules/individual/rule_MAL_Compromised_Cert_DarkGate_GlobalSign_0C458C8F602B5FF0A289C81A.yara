import "pe"

rule MAL_Compromised_Cert_DarkGate_GlobalSign_0C458C8F602B5FF0A289C81A {
   meta:
      description         = "Detects DarkGate with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-15"
      version             = "1.0"

      hash                = "e92f111b8aa01289f72c66585219861e0117c9939de56741cbb234fee55536fe"
      malware             = "DarkGate"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware was known to be multifunctional and evasive. Its main popularity was in 2024 during a period where there were open sales. See this for more information on its functionality: https://www.proofpoint.com/us/blog/email-and-cloud-threats/darkgate-malware"

      signer              = "BLVS Tech Inc."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "0c:45:8c:8f:60:2b:5f:f0:a2:89:c8:1a"
      cert_thumbprint     = "3A2166A51F50108084B9485FD8B47918A0519DD6"
      cert_valid_from     = "2025-01-15"
      cert_valid_to       = "2026-01-16"

      country             = "CA"
      state               = "Ontario"
      locality            = "Mississauga"
      email               = "???"
      rdn_serial_number   = "1122748-3"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "0c:45:8c:8f:60:2b:5f:f0:a2:89:c8:1a"
      )
}
