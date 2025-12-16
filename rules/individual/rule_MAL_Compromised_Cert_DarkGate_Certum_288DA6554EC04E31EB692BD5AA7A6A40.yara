import "pe"

rule MAL_Compromised_Cert_DarkGate_Certum_288DA6554EC04E31EB692BD5AA7A6A40 {
   meta:
      description         = "Detects DarkGate with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-04"
      version             = "1.0"

      hash                = "c4a985bce28d6863102acb148d3b47c6e7abb15875a27d43dcd0b06ca4c29433"
      malware             = "DarkGate"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware was known to be multifunctional and evasive. Its main popularity was in 2024 during a period where there were open sales. See this for more information on its functionality: https://www.proofpoint.com/us/blog/email-and-cloud-threats/darkgate-malware"

      signer              = "Clicksat Ltd"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "28:8d:a6:55:4e:c0:4e:31:eb:69:2b:d5:aa:7a:6a:40"
      cert_thumbprint     = "40857F0C79BA18E6F6EAE4915B4461C8122CC5C2"
      cert_valid_from     = "2024-07-04"
      cert_valid_to       = "2025-07-04"

      country             = "GB"
      state               = "???"
      locality            = "Ilfracombe"
      email               = "???"
      rdn_serial_number   = "12585567"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "28:8d:a6:55:4e:c0:4e:31:eb:69:2b:d5:aa:7a:6a:40"
      )
}
