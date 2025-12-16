import "pe"

rule MAL_Compromised_Cert_Batloader_SSL_com_6033E9E272BCA9961C424D5AF7258E62 {
   meta:
      description         = "Detects Batloader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-05"
      version             = "1.0"

      hash                = "b1c9d857b8c56f6c1cf164e0a521e96ec1f48ddb818f6172b66223ad42829299"
      malware             = "Batloader"
      malware_type        = "Initial access tool"
      malware_notes       = "See this article to learn more about Batloader: https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html"

      signer              = "Nuotio IT Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "60:33:e9:e2:72:bc:a9:96:1c:42:4d:5a:f7:25:8e:62"
      cert_thumbprint     = "2ED62904790ED79AFB7AD84D5E9406D65F433C96"
      cert_valid_from     = "2024-09-05"
      cert_valid_to       = "2025-09-04"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Helsinki"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "60:33:e9:e2:72:bc:a9:96:1c:42:4d:5a:f7:25:8e:62"
      )
}
