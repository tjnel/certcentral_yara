import "pe"

rule MAL_Compromised_Cert_D3F_ckLoader_UC_SSL_com_584C7B537ABF0DD673CC35C9CF040E91 {
   meta:
      description         = "Detects D3F@ckLoader - UC with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-03"
      version             = "1.0"

      hash                = "d42d30f58b5b3443212310c7fdebc2f611d5cecc6c1f924d7c948fb1b1c819ea"
      malware             = "D3F@ckLoader - UC"
      malware_type        = "Loader"
      malware_notes       = "This malware as sold was part of a service: it included both the loader and a code-signing certificate. See this for more details: https://www.esentire.com/blog/exploring-the-d3f-ck-malware-as-a-service-loader"

      signer              = "Creative Software Services Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "58:4c:7b:53:7a:bf:0d:d6:73:cc:35:c9:cf:04:0e:91"
      cert_thumbprint     = "FC925E894C131D85BEA5EABA92C3460D6CD54935"
      cert_valid_from     = "2024-04-03"
      cert_valid_to       = "2025-04-03"

      country             = "GB"
      state               = "England"
      locality            = "Treeton"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "58:4c:7b:53:7a:bf:0d:d6:73:cc:35:c9:cf:04:0e:91"
      )
}
