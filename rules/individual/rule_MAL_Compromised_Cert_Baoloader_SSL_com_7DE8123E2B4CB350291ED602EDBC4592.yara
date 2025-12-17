import "pe"

rule MAL_Compromised_Cert_Baoloader_SSL_com_7DE8123E2B4CB350291ED602EDBC4592 {
   meta:
      description         = "Detects Baoloader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-07-28"
      version             = "1.0"

      hash                = "9703d2f237c6e57dd71898dc41fb20a86da8c9a34ebd9cfb1d93a929dc8f1624"
      malware             = "Baoloader"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was originally used for adfraud but is a risk due to an arbitrary backdoor. For more information see https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/ and https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis"

      signer              = "Apollo Technologies Inc"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "7d:e8:12:3e:2b:4c:b3:50:29:1e:d6:02:ed:bc:45:92"
      cert_thumbprint     = "EB5A7872B0563D261362F00BC6AF0AFC36877A89"
      cert_valid_from     = "2023-07-28"
      cert_valid_to       = "2026-07-25"

      country             = "PA"
      state               = "???"
      locality            = "Panama City"
      email               = "???"
      rdn_serial_number   = "155722923"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "7d:e8:12:3e:2b:4c:b3:50:29:1e:d6:02:ed:bc:45:92"
      )
}
