import "pe"

rule MAL_Compromised_Cert_D3F_ckLoader_SSL_com_1595F609B85F702108D66F78373A8C1F {
   meta:
      description         = "Detects D3F@ckLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-10"
      version             = "1.0"

      hash                = "c6bb166294257e53d0d4b9ef6fe362c8cbacef5ec2bd26f98c6d7043284dec73"
      malware             = "D3F@ckLoader"
      malware_type        = "Loader"
      malware_notes       = "This malware as sold was part of a service: it included both the loader and a code-signing certificate. See this for more details: https://www.esentire.com/blog/exploring-the-d3f-ck-malware-as-a-service-loader"

      signer              = "Stradgate Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "15:95:f6:09:b8:5f:70:21:08:d6:6f:78:37:3a:8c:1f"
      cert_thumbprint     = "3B9A5962CD3A79E3801C47D1F55785FA34DF473A"
      cert_valid_from     = "2024-09-10"
      cert_valid_to       = "2025-09-10"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "10291410"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "15:95:f6:09:b8:5f:70:21:08:d6:6f:78:37:3a:8c:1f"
      )
}
