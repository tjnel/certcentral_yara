import "pe"

rule MAL_Compromised_Cert_D3F_ckLoader_SSL_com_60FAC7DEA1D94581674A68276485FCC5 {
   meta:
      description         = "Detects D3F@ckLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-29"
      version             = "1.0"

      hash                = "ee4012f2a0dfd5a557b244c850b01484f52cda93aaed423398b2ef859d3b907d"
      malware             = "D3F@ckLoader"
      malware_type        = "Loader"
      malware_notes       = "This malware as sold was part of a service: it included both the loader and a code-signing certificate. See this for more details: https://www.esentire.com/blog/exploring-the-d3f-ck-malware-as-a-service-loader"

      signer              = "Binary Intellect Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "60:fa:c7:de:a1:d9:45:81:67:4a:68:27:64:85:fc:c5"
      cert_thumbprint     = "A0958D50807E1F6EC11A45A6A0332D9A12E15A25"
      cert_valid_from     = "2024-05-29"
      cert_valid_to       = "2025-05-29"

      country             = "GB"
      state               = "???"
      locality            = "Manchester"
      email               = "???"
      rdn_serial_number   = "12996464"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "60:fa:c7:de:a1:d9:45:81:67:4a:68:27:64:85:fc:c5"
      )
}
