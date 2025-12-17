import "pe"

rule MAL_Compromised_Cert_D3F_ckLoader_SSL_com_3724A8692FD4C9C2ABE250C83FE61A0D {
   meta:
      description         = "Detects D3F@ckLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-16"
      version             = "1.0"

      hash                = "69184f6861718a2d47ca10f0e7b0b9790f46c2bdc50c94ee5050dc5bebfb380f"
      malware             = "D3F@ckLoader"
      malware_type        = "Loader"
      malware_notes       = "This malware as sold was part of a service: it included both the loader and a code-signing certificate. See this for more details: https://www.esentire.com/blog/exploring-the-d3f-ck-malware-as-a-service-loader"

      signer              = "DIGEN LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "37:24:a8:69:2f:d4:c9:c2:ab:e2:50:c8:3f:e6:1a:0d"
      cert_thumbprint     = "905127E4799A152D516273EE79A58DB9CCAAEC87"
      cert_valid_from     = "2024-07-16"
      cert_valid_to       = "2025-07-16"

      country             = "GB"
      state               = "???"
      locality            = "Coventry"
      email               = "???"
      rdn_serial_number   = "12765402"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "37:24:a8:69:2f:d4:c9:c2:ab:e2:50:c8:3f:e6:1a:0d"
      )
}
