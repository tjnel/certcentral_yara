import "pe"

rule MAL_Compromised_Cert_BatLoader_Certum_5044BD6320C1B4CC47D56CC56C1E36D8 {
   meta:
      description         = "Detects BatLoader with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-20"
      version             = "1.0"

      hash                = "4b2557cf1e0fa54051631931fd164edbfc5e1c0986aa8e776d3fe446a670c10a"
      malware             = "BatLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "See this article to learn more about Batloader: https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html"

      signer              = "Dalian Tester Software Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "50:44:bd:63:20:c1:b4:cc:47:d5:6c:c5:6c:1e:36:d8"
      cert_thumbprint     = "A0F9C688EDA204A5B829116387BCF91A90F9FDFF"
      cert_valid_from     = "2024-06-20"
      cert_valid_to       = "2025-06-20"

      country             = "CN"
      state               = "Liaoning"
      locality            = "Dalian"
      email               = "???"
      rdn_serial_number   = "91210231MA107A346U"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "50:44:bd:63:20:c1:b4:cc:47:d5:6c:c5:6c:1e:36:d8"
      )
}
