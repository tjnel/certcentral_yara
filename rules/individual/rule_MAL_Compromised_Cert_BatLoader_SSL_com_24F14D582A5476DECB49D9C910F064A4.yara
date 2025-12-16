import "pe"

rule MAL_Compromised_Cert_BatLoader_SSL_com_24F14D582A5476DECB49D9C910F064A4 {
   meta:
      description         = "Detects BatLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-09-19"
      version             = "1.0"

      hash                = "97ac5e537d38415ccc56bd114e7b6f0053e894032c506eea37896779b6c68caf"
      malware             = "BatLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "See this article to learn more about Batloader: https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html"

      signer              = "Ivosaq Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "24:f1:4d:58:2a:54:76:de:cb:49:d9:c9:10:f0:64:a4"
      cert_thumbprint     = "FBA3137257B30139FD4AEBD07FCED8584E0155FF"
      cert_valid_from     = "2023-09-19"
      cert_valid_to       = "2024-09-18"

      country             = "GB"
      state               = "???"
      locality            = "Poole"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "24:f1:4d:58:2a:54:76:de:cb:49:d9:c9:10:f0:64:a4"
      )
}
