import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Sectigo_00C86D943E4E146E5FDF9694F06DA41F2B {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-16"
      version             = "1.0"

      hash                = "a04f1e64fd7e2ef6decbfd2e26ad2a3066862fbe039a3bbed5cc9b6eacd4edf9"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware leverages cloud hosting to hold additional components. The components are TASLogin and its associated DLL: medium.com/@anyrun/zhong-stealer-analysis-new-malware-targeting-fintech-and-cryptocurrency-71d4a3cce42c"

      signer              = "Harman International Industries, Incorporated"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV E36"
      cert_serial         = "00:c8:6d:94:3e:4e:14:6e:5f:df:96:94:f0:6d:a4:1f:2b"
      cert_thumbprint     = "7DD79011F697349E20682B25CFD670EACF1CED73"
      cert_valid_from     = "2025-05-16"
      cert_valid_to       = "2026-04-28"

      country             = "US"
      state               = "Connecticut"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "1080291"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV E36" and
         sig.serial == "00:c8:6d:94:3e:4e:14:6e:5f:df:96:94:f0:6d:a4:1f:2b"
      )
}
