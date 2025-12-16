import "pe"

rule MAL_Compromised_Cert_BaoLoader_DigiCert_035A3901296CAAD75132EBA7C9116DB0 {
   meta:
      description         = "Detects BaoLoader with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-01-21"
      version             = "1.0"

      hash                = "5c80c6a527f9c0d57c5411d9a9192235cfa88351a3d372ae05e48f36b6e41a80"
      malware             = "BaoLoader"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was originally used for adfraud but is a risk due to an arbitrary backdoor. For more information see https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/ and https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis"

      signer              = "Eclipse Media Inc."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "03:5a:39:01:29:6c:aa:d7:51:32:eb:a7:c9:11:6d:b0"
      cert_thumbprint     = "5D69F8B3A86EEA553A2F5B148542923E8ED907DF"
      cert_valid_from     = "2022-01-21"
      cert_valid_to       = "2023-01-21"

      country             = "PA"
      state               = "Panama"
      locality            = "Panama City"
      email               = "???"
      rdn_serial_number   = "155704432"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "03:5a:39:01:29:6c:aa:d7:51:32:eb:a7:c9:11:6d:b0"
      )
}
