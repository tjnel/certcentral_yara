import "pe"

rule MAL_Compromised_Cert_D3F_ckLoader_SSL_com_12697443E6FE59C5E187059F7161B615 {
   meta:
      description         = "Detects D3F@ckLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-12"
      version             = "1.0"

      hash                = "7ef83d9bbc288d5140ba999cbb7f65c7c2b25c0120bc7a7a2f0fa93bf8f86b97"
      malware             = "D3F@ckLoader"
      malware_type        = "Loader"
      malware_notes       = "This malware as sold was part of a service: it included both the loader and a code-signing certificate. See this for more details: https://www.esentire.com/blog/exploring-the-d3f-ck-malware-as-a-service-loader"

      signer              = "Neural Code Technologies Inc."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "12:69:74:43:e6:fe:59:c5:e1:87:05:9f:71:61:b6:15"
      cert_thumbprint     = "65DBAEEF00FC82E957E01D7B37502C0B73EADE31"
      cert_valid_from     = "2024-04-12"
      cert_valid_to       = "2025-04-12"

      country             = "CA"
      state               = "Ontario"
      locality            = "Whitby"
      email               = "???"
      rdn_serial_number   = "1011671-8"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "12:69:74:43:e6:fe:59:c5:e1:87:05:9f:71:61:b6:15"
      )
}
