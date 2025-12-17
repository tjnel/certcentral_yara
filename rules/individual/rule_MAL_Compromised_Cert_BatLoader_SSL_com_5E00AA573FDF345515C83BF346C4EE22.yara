import "pe"

rule MAL_Compromised_Cert_BatLoader_SSL_com_5E00AA573FDF345515C83BF346C4EE22 {
   meta:
      description         = "Detects BatLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-08"
      version             = "1.0"

      hash                = "8d1f6fac51e8130f9b769f77220a7d142aa0458cf51677375967015c7a29f8f4"
      malware             = "BatLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "See this article to learn more about Batloader: https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html"

      signer              = "LMC BIOPOLYMERS LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "5e:00:aa:57:3f:df:34:55:15:c8:3b:f3:46:c4:ee:22"
      cert_thumbprint     = "715C53A149C91A977841F23441B028A59F0EDE25"
      cert_valid_from     = "2024-05-08"
      cert_valid_to       = "2024-09-17"

      country             = "GB"
      state               = "???"
      locality            = "Belfast"
      email               = "???"
      rdn_serial_number   = "NI656273"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "5e:00:aa:57:3f:df:34:55:15:c8:3b:f3:46:c4:ee:22"
      )
}
