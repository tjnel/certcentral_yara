import "pe"

rule MAL_Compromised_Cert_BrowserRAT_SSL_com_3A2844FBA53EED9F3C50390F0FB51F84 {
   meta:
      description         = "Detects BrowserRAT with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-22"
      version             = "1.0"

      hash                = "b1ce4ebb517a44e305e22ef9221c1b66c3e7f9327f4ae007a4e18144f4f97add"
      malware             = "BrowserRAT"
      malware_type        = "Backdoor"
      malware_notes       = "Malware uses scheduled task for persistence, can download and execute AES encrypted payloads. See deeper analysis here: https://blog.lukeacha.com/2025/11/primepdfconvert-yapa-yet-another-pdf.html"

      signer              = "Beyond Ideas LLC"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "3a:28:44:fb:a5:3e:ed:9f:3c:50:39:0f:0f:b5:1f:84"
      cert_thumbprint     = "73C966E6EEC68ED95611519F97D921AEE6328624"
      cert_valid_from     = "2025-08-22"
      cert_valid_to       = "2026-07-24"

      country             = "US"
      state               = "Texas"
      locality            = "Austin"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "3a:28:44:fb:a5:3e:ed:9f:3c:50:39:0f:0f:b5:1f:84"
      )
}
