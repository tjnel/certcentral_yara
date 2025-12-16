import "pe"

rule MAL_Compromised_Cert_Baoloader_SSL_com_3FEBAE41896885E91FDB20E0950C6054 {
   meta:
      description         = "Detects Baoloader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-13"
      version             = "1.0"

      hash                = "1ac61435e8a508647724c7796406107b43c3c1e546782a9bcf14db88ddd5f75d"
      malware             = "Baoloader"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was originally used for adfraud but is a risk due to an arbitrary backdoor. For more information see https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/ and https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis"

      signer              = "ECHO INFINI SDN. BHD."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "3f:eb:ae:41:89:68:85:e9:1f:db:20:e0:95:0c:60:54"
      cert_thumbprint     = "29338264019B62D11F9C6C4B5A69B78B899B4DF6"
      cert_valid_from     = "2025-01-13"
      cert_valid_to       = "2027-01-13"

      country             = "MY"
      state               = "Johor"
      locality            = "Skudai"
      email               = "???"
      rdn_serial_number   = "202401031184"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "3f:eb:ae:41:89:68:85:e9:1f:db:20:e0:95:0c:60:54"
      )
}
