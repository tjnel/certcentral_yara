import "pe"

rule MAL_Compromised_Cert_D3F_ckLoader_Certum_3A8AE46D9DE62F166EB621649B6A6E2E {
   meta:
      description         = "Detects D3F@ckLoader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-19"
      version             = "1.0"

      hash                = "125b397a627f37c70e2cf2461c6a6583a975ba78617995751cacb32525a3b875"
      malware             = "D3F@ckLoader"
      malware_type        = "Loader"
      malware_notes       = "This malware as sold was part of a service: it included both the loader and a code-signing certificate. See this for more details: https://www.esentire.com/blog/exploring-the-d3f-ck-malware-as-a-service-loader"

      signer              = "Taelos Ltd"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "3a:8a:e4:6d:9d:e6:2f:16:6e:b6:21:64:9b:6a:6e:2e"
      cert_thumbprint     = "32A6FB73AE60BDC0287701BD75DC26881F8E2036"
      cert_valid_from     = "2024-06-19"
      cert_valid_to       = "2025-06-19"

      country             = "GB"
      state               = "???"
      locality            = "Hove"
      email               = "???"
      rdn_serial_number   = "12106360"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "3a:8a:e4:6d:9d:e6:2f:16:6e:b6:21:64:9b:6a:6e:2e"
      )
}
