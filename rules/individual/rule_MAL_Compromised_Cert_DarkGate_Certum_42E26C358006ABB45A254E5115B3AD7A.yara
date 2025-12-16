import "pe"

rule MAL_Compromised_Cert_DarkGate_Certum_42E26C358006ABB45A254E5115B3AD7A {
   meta:
      description         = "Detects DarkGate with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-10-20"
      version             = "1.0"

      hash                = "1bc06334849768ebbd7afff675e4e3196984d00c495395ddb9050c8c5f780381"
      malware             = "DarkGate"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware was known to be multifunctional and evasive. Its main popularity was in 2024 during a period where there were open sales. See this for more information on its functionality: https://www.proofpoint.com/us/blog/email-and-cloud-threats/darkgate-malware"

      signer              = "INTERREX - SP. Z O.O."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "42:e2:6c:35:80:06:ab:b4:5a:25:4e:51:15:b3:ad:7a"
      cert_thumbprint     = "AC9FD222C4CD5AB74DEE4C9F0D72B4746984F049"
      cert_valid_from     = "2023-10-20"
      cert_valid_to       = "2024-10-19"

      country             = "PL"
      state               = "mazowieckie"
      locality            = "Warszawa"
      email               = "???"
      rdn_serial_number   = "0000165162"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "42:e2:6c:35:80:06:ab:b4:5a:25:4e:51:15:b3:ad:7a"
      )
}
