import "pe"

rule MAL_Compromised_Cert_DarkGate_Certum_58C66807FCA8F78EB99DBCDE4AD64CF0 {
   meta:
      description         = "Detects DarkGate with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-04"
      version             = "1.0"

      hash                = "cf5ae6d4eb9b986c8178740f0948397efb11b95b1c40d8b30ebbbfe36e726e47"
      malware             = "DarkGate"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware was known to be multifunctional and evasive. Its main popularity was in 2024 during a period where there were open sales. See this for more information on its functionality: https://www.proofpoint.com/us/blog/email-and-cloud-threats/darkgate-malware"

      signer              = "Huzhou Banka Clothing Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "58:c6:68:07:fc:a8:f7:8e:b9:9d:bc:de:4a:d6:4c:f0"
      cert_thumbprint     = "1E2FA1CCE8322BCED8504CB5B5A7BB215BB7E57C"
      cert_valid_from     = "2024-06-04"
      cert_valid_to       = "2025-06-04"

      country             = "CN"
      state               = "Zhejiang"
      locality            = "Huzhou"
      email               = "???"
      rdn_serial_number   = "91330502MA2JJNRA84"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "58:c6:68:07:fc:a8:f7:8e:b9:9d:bc:de:4a:d6:4c:f0"
      )
}
