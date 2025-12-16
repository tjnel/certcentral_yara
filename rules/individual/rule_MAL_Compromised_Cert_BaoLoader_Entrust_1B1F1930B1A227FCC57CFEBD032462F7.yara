import "pe"

rule MAL_Compromised_Cert_BaoLoader_Entrust_1B1F1930B1A227FCC57CFEBD032462F7 {
   meta:
      description         = "Detects BaoLoader with compromised cert (Entrust)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-04-12"
      version             = "1.0"

      hash                = "e505e4bc6c76f8ccd1d626832d1d5d5d2852a5c78016c43bdc2f502af6e40396"
      malware             = "BaoLoader"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was originally used for adfraud but is a risk due to an arbitrary backdoor. For more information see https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/ and https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis"

      signer              = "Drake Media Inc"
      cert_issuer_short   = "Entrust"
      cert_issuer         = "Entrust Extended Validation Code Signing CA - EVCS2"
      cert_serial         = "1b:1f:19:30:b1:a2:27:fc:c5:7c:fe:bd:03:24:62:f7"
      cert_thumbprint     = "0269E7886EB31830E2488421756D282E2C481CDC"
      cert_valid_from     = "2023-04-12"
      cert_valid_to       = "2025-04-11"

      country             = "PA"
      state               = "Panamá"
      locality            = "Panama City"
      email               = "???"
      rdn_serial_number   = "155704428"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Entrust Extended Validation Code Signing CA - EVCS2" and
         sig.serial == "1b:1f:19:30:b1:a2:27:fc:c5:7c:fe:bd:03:24:62:f7"
      )
}
