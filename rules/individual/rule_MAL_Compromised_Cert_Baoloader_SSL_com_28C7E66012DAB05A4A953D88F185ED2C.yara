import "pe"

rule MAL_Compromised_Cert_Baoloader_SSL_com_28C7E66012DAB05A4A953D88F185ED2C {
   meta:
      description         = "Detects Baoloader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-24"
      version             = "1.0"

      hash                = "71edb9f9f757616fe62a49f2d5b55441f91618904517337abd9d0725b07c2a51"
      malware             = "Baoloader"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was originally used for adfraud but is a risk due to an arbitrary backdoor. For more information see https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/ and https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis"

      signer              = "GLINT SOFTWARE SDN. BHD."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "28:c7:e6:60:12:da:b0:5a:4a:95:3d:88:f1:85:ed:2c"
      cert_thumbprint     = "99201EEE9807D24851026A8E8884E4C40245FAC7"
      cert_valid_from     = "2025-04-24"
      cert_valid_to       = "2026-04-24"

      country             = "MY"
      state               = "Johor"
      locality            = "Skudai"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "28:c7:e6:60:12:da:b0:5a:4a:95:3d:88:f1:85:ed:2c"
      )
}
