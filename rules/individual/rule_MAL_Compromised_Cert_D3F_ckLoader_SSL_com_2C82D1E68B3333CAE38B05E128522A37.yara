import "pe"

rule MAL_Compromised_Cert_D3F_ckLoader_SSL_com_2C82D1E68B3333CAE38B05E128522A37 {
   meta:
      description         = "Detects D3F@ckLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-19"
      version             = "1.0"

      hash                = "0a27e7cbb5ed1aa3e517d4d1d3fa1974409cb3379707853cfa58be4181e24827"
      malware             = "D3F@ckLoader"
      malware_type        = "Loader"
      malware_notes       = "This malware as sold was part of a service: it included both the loader and a code-signing certificate. See this for more details: https://www.esentire.com/blog/exploring-the-d3f-ck-malware-as-a-service-loader"

      signer              = "Keeper Systems Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "2c:82:d1:e6:8b:33:33:ca:e3:8b:05:e1:28:52:2a:37"
      cert_thumbprint     = "F0BB5D277B6396D23F53813F3D3EF127CD7B3BB9"
      cert_valid_from     = "2024-07-19"
      cert_valid_to       = "2025-07-19"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "12409387"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "2c:82:d1:e6:8b:33:33:ca:e3:8b:05:e1:28:52:2a:37"
      )
}
