import "pe"

rule MAL_Compromised_Cert_D3F_ckLoader_SSL_com_71F122B17613E367D58FFCD08DEA6AF4 {
   meta:
      description         = "Detects D3F@ckLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-20"
      version             = "1.0"

      hash                = "398b47cfbdba5e8512998a2823d6ab493b3b0ed0cec0c583d0907b9f4e86febb"
      malware             = "D3F@ckLoader"
      malware_type        = "Loader"
      malware_notes       = "This malware as sold was part of a service: it included both the loader and a code-signing certificate. See this for more details: https://www.esentire.com/blog/exploring-the-d3f-ck-malware-as-a-service-loader"

      signer              = "Mosak Soft Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "71:f1:22:b1:76:13:e3:67:d5:8f:fc:d0:8d:ea:6a:f4"
      cert_thumbprint     = "320ECD6F82F874CDC0CDD2EAEF8164298E9943F9"
      cert_valid_from     = "2024-08-20"
      cert_valid_to       = "2025-08-20"

      country             = "NZ"
      state               = "Auckland Region"
      locality            = "Auckland"
      email               = "???"
      rdn_serial_number   = "8177681"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "71:f1:22:b1:76:13:e3:67:d5:8f:fc:d0:8d:ea:6a:f4"
      )
}
