import "pe"

rule MAL_Compromised_Cert_D3F_ckLoader_SSL_com_4DEBD035CAFE5E73D5C7E0960D450AFD {
   meta:
      description         = "Detects D3F@ckLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-30"
      version             = "1.0"

      hash                = "d04530a24016d143e32bedca60b7d2b6a6ea41acd2b7e7edb29c2221cf166553"
      malware             = "D3F@ckLoader"
      malware_type        = "Loader"
      malware_notes       = "This malware as sold was part of a service: it included both the loader and a code-signing certificate. See this for more details: https://www.esentire.com/blog/exploring-the-d3f-ck-malware-as-a-service-loader"

      signer              = "Tenet Tech Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "4d:eb:d0:35:ca:fe:5e:73:d5:c7:e0:96:0d:45:0a:fd"
      cert_thumbprint     = "DCA5A873EEE4F19E6884A304D295E969F8EBE5E4"
      cert_valid_from     = "2024-05-30"
      cert_valid_to       = "2025-05-30"

      country             = "GB"
      state               = "???"
      locality            = "Smethwick"
      email               = "???"
      rdn_serial_number   = "12986986"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "4d:eb:d0:35:ca:fe:5e:73:d5:c7:e0:96:0d:45:0a:fd"
      )
}
