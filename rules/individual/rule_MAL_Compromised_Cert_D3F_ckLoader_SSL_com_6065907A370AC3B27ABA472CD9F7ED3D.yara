import "pe"

rule MAL_Compromised_Cert_D3F_ckLoader_SSL_com_6065907A370AC3B27ABA472CD9F7ED3D {
   meta:
      description         = "Detects D3F@ckLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-21"
      version             = "1.0"

      hash                = "30e554562e154d288bcd3eb43897507d58ac410ff47ed75b4edda651c033a64c"
      malware             = "D3F@ckLoader"
      malware_type        = "Loader"
      malware_notes       = "This malware as sold was part of a service: it included both the loader and a code-signing certificate. See this for more details: https://www.esentire.com/blog/exploring-the-d3f-ck-malware-as-a-service-loader"

      signer              = "Strategc Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "60:65:90:7a:37:0a:c3:b2:7a:ba:47:2c:d9:f7:ed:3d"
      cert_thumbprint     = "E098218628CF43BB0A0B14ADFD827402B403D9A3"
      cert_valid_from     = "2024-08-21"
      cert_valid_to       = "2025-08-21"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "12011673"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "60:65:90:7a:37:0a:c3:b2:7a:ba:47:2c:d9:f7:ed:3d"
      )
}
