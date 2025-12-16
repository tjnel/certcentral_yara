import "pe"

rule MAL_Compromised_Cert_D3F_ckLoader_SSL_com_0FF89952DE8FDAF149D86308829F12EE {
   meta:
      description         = "Detects D3F@ckLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-12"
      version             = "1.0"

      hash                = "964d609b0fcf5ade742e9e6fe504bdfbe131b84f3cbab5ed59e977bd4036f405"
      malware             = "D3F@ckLoader"
      malware_type        = "Loader"
      malware_notes       = "This malware as sold was part of a service: it included both the loader and a code-signing certificate. See this for more details: https://www.esentire.com/blog/exploring-the-d3f-ck-malware-as-a-service-loader"

      signer              = "Ayog Tech Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "0f:f8:99:52:de:8f:da:f1:49:d8:63:08:82:9f:12:ee"
      cert_thumbprint     = "FC4535994E75B0DC4820C8EB258298986FBD8945"
      cert_valid_from     = "2024-04-12"
      cert_valid_to       = "2025-04-12"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "07389721"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "0f:f8:99:52:de:8f:da:f1:49:d8:63:08:82:9f:12:ee"
      )
}
