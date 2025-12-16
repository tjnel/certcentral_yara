import "pe"

rule MAL_Compromised_Cert_Batloader_Certum_35B49EE870AEA532E6EF0A4987105C8F {
   meta:
      description         = "Detects Batloader with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-09-14"
      version             = "1.0"

      hash                = "e8492d0af0f44af35b753e7f75242da53c27b089bb11d44520724ae74428c48e"
      malware             = "Batloader"
      malware_type        = "Initial access tool"
      malware_notes       = "See this article to learn more about Batloader: https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html"

      signer              = "Kancelaria Adwokacka Adwokat Aleksandra Krzemińska"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "35:b4:9e:e8:70:ae:a5:32:e6:ef:0a:49:87:10:5c:8f"
      cert_thumbprint     = "94AEACEBF2A8A825C3B10DBC7572C38B96099AF1"
      cert_valid_from     = "2022-09-14"
      cert_valid_to       = "2023-09-14"

      country             = "PL"
      state               = "małopolskie"
      locality            = "Kraków"
      email               = "???"
      rdn_serial_number   = "383601062"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "35:b4:9e:e8:70:ae:a5:32:e6:ef:0a:49:87:10:5c:8f"
      )
}
