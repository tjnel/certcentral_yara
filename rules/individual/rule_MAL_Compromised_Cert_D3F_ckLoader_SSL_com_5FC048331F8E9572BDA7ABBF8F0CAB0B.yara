import "pe"

rule MAL_Compromised_Cert_D3F_ckLoader_SSL_com_5FC048331F8E9572BDA7ABBF8F0CAB0B {
   meta:
      description         = "Detects D3F@ckLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-03-14"
      version             = "1.0"

      hash                = "0f4262fcff68c06c8d0be7184263135d1dce951b52af8b6010e0dd18fe7f4937"
      malware             = "D3F@ckLoader"
      malware_type        = "Loader"
      malware_notes       = "This malware as sold was part of a service: it included both the loader and a code-signing certificate. See this for more details: https://www.esentire.com/blog/exploring-the-d3f-ck-malware-as-a-service-loader"

      signer              = "Primalspeed Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "5f:c0:48:33:1f:8e:95:72:bd:a7:ab:bf:8f:0c:ab:0b"
      cert_thumbprint     = "26CF92F790EC122CF6B38887CFDF080A923377F3"
      cert_valid_from     = "2024-03-14"
      cert_valid_to       = "2025-03-14"

      country             = "GB"
      state               = "???"
      locality            = "Hove"
      email               = "???"
      rdn_serial_number   = "07850286"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "5f:c0:48:33:1f:8e:95:72:bd:a7:ab:bf:8f:0c:ab:0b"
      )
}
