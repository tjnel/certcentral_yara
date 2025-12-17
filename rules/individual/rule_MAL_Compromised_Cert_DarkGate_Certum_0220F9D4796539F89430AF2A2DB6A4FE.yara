import "pe"

rule MAL_Compromised_Cert_DarkGate_Certum_0220F9D4796539F89430AF2A2DB6A4FE {
   meta:
      description         = "Detects DarkGate with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-16"
      version             = "1.0"

      hash                = "3a8f32e6d315e58026ef0e8b91c311cf4cfedd7f71fa1c7e7f7f54f906c45d42"
      malware             = "DarkGate"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware was known to be multifunctional and evasive. Its main popularity was in 2024 during a period where there were open sales. See this for more information on its functionality: https://www.proofpoint.com/us/blog/email-and-cloud-threats/darkgate-malware"

      signer              = "DauLue Intention Fly Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "02:20:f9:d4:79:65:39:f8:94:30:af:2a:2d:b6:a4:fe"
      cert_thumbprint     = "8AE22A007A0103E032F4D41F6926F834AE9E1833"
      cert_valid_from     = "2024-04-16"
      cert_valid_to       = "2025-04-16"

      country             = "CN"
      state               = "Liaoning"
      locality            = "Dalian"
      email               = "???"
      rdn_serial_number   = "91210242MA0YGH36XJ"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "02:20:f9:d4:79:65:39:f8:94:30:af:2a:2d:b6:a4:fe"
      )
}
