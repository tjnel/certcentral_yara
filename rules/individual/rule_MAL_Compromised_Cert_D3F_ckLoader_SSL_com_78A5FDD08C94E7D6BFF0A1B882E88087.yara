import "pe"

rule MAL_Compromised_Cert_D3F_ckLoader_SSL_com_78A5FDD08C94E7D6BFF0A1B882E88087 {
   meta:
      description         = "Detects D3F@ckLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-25"
      version             = "1.0"

      hash                = "b25005b4361d67a5fb56513b50f59a1995856fbb8de32d5e5dec51f26744220d"
      malware             = "D3F@ckLoader"
      malware_type        = "Loader"
      malware_notes       = "This malware as sold was part of a service: it included both the loader and a code-signing certificate. See this for more details: https://www.esentire.com/blog/exploring-the-d3f-ck-malware-as-a-service-loader"

      signer              = "SEEONEE LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "78:a5:fd:d0:8c:94:e7:d6:bf:f0:a1:b8:82:e8:80:87"
      cert_thumbprint     = "F3BF3DACCD411EB9A1207EA86D8B208FB894D0E1"
      cert_valid_from     = "2024-07-25"
      cert_valid_to       = "2025-07-25"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "11949474"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "78:a5:fd:d0:8c:94:e7:d6:bf:f0:a1:b8:82:e8:80:87"
      )
}
