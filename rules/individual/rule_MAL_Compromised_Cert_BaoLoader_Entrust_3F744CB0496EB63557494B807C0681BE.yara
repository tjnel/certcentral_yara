import "pe"

rule MAL_Compromised_Cert_BaoLoader_Entrust_3F744CB0496EB63557494B807C0681BE {
   meta:
      description         = "Detects BaoLoader with compromised cert (Entrust)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-21"
      version             = "1.0"

      hash                = "6ec07c1d2dc566d59a7576cc4a89c605bcfc8abd414c77338c940fb8e3ed5f1a"
      malware             = "BaoLoader"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was originally used for adfraud but is a risk due to an arbitrary backdoor. For more information see https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/ and https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis"

      signer              = "Byte Media Sdn Bhd"
      cert_issuer_short   = "Entrust"
      cert_issuer         = "Entrust Extended Validation Code Signing CA - EVCS2"
      cert_serial         = "3f:74:4c:b0:49:6e:b6:35:57:49:4b:80:7c:06:81:be"
      cert_thumbprint     = "61CE7E9E22608EBC708C42B1CE5E842395C437D1"
      cert_valid_from     = "2024-08-21"
      cert_valid_to       = "2025-08-21"

      country             = "MY"
      state               = "Johor"
      locality            = "Skudai"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Entrust Extended Validation Code Signing CA - EVCS2" and
         sig.serial == "3f:74:4c:b0:49:6e:b6:35:57:49:4b:80:7c:06:81:be"
      )
}
