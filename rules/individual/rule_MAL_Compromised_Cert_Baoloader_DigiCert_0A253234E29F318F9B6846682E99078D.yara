import "pe"

rule MAL_Compromised_Cert_Baoloader_DigiCert_0A253234E29F318F9B6846682E99078D {
   meta:
      description         = "Detects Baoloader with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-02-28"
      version             = "1.0"

      hash                = "2926e6a08ac1e28928573996cd82bdc19054b8ae7642b91765aab1a16e5c7128"
      malware             = "Baoloader"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was originally used for adfraud but is a risk due to an arbitrary backdoor. For more information see https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/ and https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis"

      signer              = "Millennial Media Inc."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0a:25:32:34:e2:9f:31:8f:9b:68:46:68:2e:99:07:8d"
      cert_thumbprint     = "A00D344BDC112328D1969ADF9DECBE8A96035DC3"
      cert_valid_from     = "2022-02-28"
      cert_valid_to       = "2023-03-01"

      country             = "PA"
      state               = "Panama"
      locality            = "Panama City"
      email               = "???"
      rdn_serial_number   = "155704409"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0a:25:32:34:e2:9f:31:8f:9b:68:46:68:2e:99:07:8d"
      )
}
