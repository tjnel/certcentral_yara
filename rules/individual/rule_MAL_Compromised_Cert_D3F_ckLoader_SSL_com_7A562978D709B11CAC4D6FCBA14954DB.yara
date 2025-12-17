import "pe"

rule MAL_Compromised_Cert_D3F_ckLoader_SSL_com_7A562978D709B11CAC4D6FCBA14954DB {
   meta:
      description         = "Detects D3F@ckLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-10"
      version             = "1.0"

      hash                = "e4799b54d657d4d9c64d49bc936772cdcca6329e05be972d3b1ec6ad08d8f4ea"
      malware             = "D3F@ckLoader"
      malware_type        = "Loader"
      malware_notes       = "This malware as sold was part of a service: it included both the loader and a code-signing certificate. See this for more details: https://www.esentire.com/blog/exploring-the-d3f-ck-malware-as-a-service-loader"

      signer              = "Paul Garner Consulting Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "7a:56:29:78:d7:09:b1:1c:ac:4d:6f:cb:a1:49:54:db"
      cert_thumbprint     = "E019D7719F55161534BB0C37DFFEFF1EF564AC31"
      cert_valid_from     = "2024-09-10"
      cert_valid_to       = "2025-09-10"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "09714891"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "7a:56:29:78:d7:09:b1:1c:ac:4d:6f:cb:a1:49:54:db"
      )
}
