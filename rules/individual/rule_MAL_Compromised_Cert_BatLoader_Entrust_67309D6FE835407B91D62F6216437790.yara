import "pe"

rule MAL_Compromised_Cert_BatLoader_Entrust_67309D6FE835407B91D62F6216437790 {
   meta:
      description         = "Detects BatLoader with compromised cert (Entrust)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-01-28"
      version             = "1.0"

      hash                = "fddf36adfee67f1deb84c18a800f847c182c15fe21e03268bbb0f0b489640dac"
      malware             = "BatLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "See this article to learn more about Batloader: https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html"

      signer              = "Pinesville Ltd"
      cert_issuer_short   = "Entrust"
      cert_issuer         = "Entrust Extended Validation Code Signing CA - EVCS2"
      cert_serial         = "67:30:9d:6f:e8:35:40:7b:91:d6:2f:62:16:43:77:90"
      cert_thumbprint     = "E7B974BC359C564CD042BA1BDC5DF9C0226A90E7"
      cert_valid_from     = "2023-01-28"
      cert_valid_to       = "2024-01-28"

      country             = "GB"
      state               = "???"
      locality            = "Enniskillen"
      email               = "???"
      rdn_serial_number   = "NI650898"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Entrust Extended Validation Code Signing CA - EVCS2" and
         sig.serial == "67:30:9d:6f:e8:35:40:7b:91:d6:2f:62:16:43:77:90"
      )
}
