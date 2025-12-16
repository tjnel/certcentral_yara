import "pe"

rule MAL_Compromised_Cert_DarkGate_Certum_6DFFAF77D8C06AF0EF1E2A88CFE4360B {
   meta:
      description         = "Detects DarkGate with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-07"
      version             = "1.0"

      hash                = "2fa83a1f4b3196a87645d4e71c3a486c7eb433ccb462c85888d5a5dee2abe2e2"
      malware             = "DarkGate"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware was known to be multifunctional and evasive. Its main popularity was in 2024 during a period where there were open sales. See this for more information on its functionality: https://www.proofpoint.com/us/blog/email-and-cloud-threats/darkgate-malware"

      signer              = "Pinchao (Shenzhen) Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "6d:ff:af:77:d8:c0:6a:f0:ef:1e:2a:88:cf:e4:36:0b"
      cert_thumbprint     = "443CAD90EB0711571D60B7DF7B1DBC7F97C3DCC2"
      cert_valid_from     = "2024-10-07"
      cert_valid_to       = "2025-10-07"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Shenzhen"
      email               = "???"
      rdn_serial_number   = "91440300596794584L"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "6d:ff:af:77:d8:c0:6a:f0:ef:1e:2a:88:cf:e4:36:0b"
      )
}
