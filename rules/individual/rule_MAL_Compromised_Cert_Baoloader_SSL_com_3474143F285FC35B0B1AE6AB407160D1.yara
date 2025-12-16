import "pe"

rule MAL_Compromised_Cert_Baoloader_SSL_com_3474143F285FC35B0B1AE6AB407160D1 {
   meta:
      description         = "Detects Baoloader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-13"
      version             = "1.0"

      hash                = "cf5194e7f63de52903b5d61109fd0d898b73dd3a07512e151077fba23cdf4800"
      malware             = "Baoloader"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was originally used for adfraud but is a risk due to an arbitrary backdoor. For more information see https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/ and https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis"

      signer              = "ECHO INFINI SDN. BHD."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "34:74:14:3f:28:5f:c3:5b:0b:1a:e6:ab:40:71:60:d1"
      cert_thumbprint     = "7533D9D9C5241D0E031C21304C6A3FF064F79072"
      cert_valid_from     = "2025-01-13"
      cert_valid_to       = "2027-01-13"

      country             = "MY"
      state               = "Johor"
      locality            = "Skudai"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "34:74:14:3f:28:5f:c3:5b:0b:1a:e6:ab:40:71:60:d1"
      )
}
