import "pe"

rule MAL_Compromised_Cert_D3F_ckLoader_SSL_com_7712F772C44D3360D635863E7414F34B {
   meta:
      description         = "Detects D3F@ckLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-03"
      version             = "1.0"

      hash                = "0b5352660dd555c0ab55ab90020a36b1f34fe9debd312c4649606adab6c957cf"
      malware             = "D3F@ckLoader"
      malware_type        = "Loader"
      malware_notes       = "This malware as sold was part of a service: it included both the loader and a code-signing certificate. See this for more details: https://www.esentire.com/blog/exploring-the-d3f-ck-malware-as-a-service-loader"

      signer              = "Jlf Software Development ApS"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "77:12:f7:72:c4:4d:33:60:d6:35:86:3e:74:14:f3:4b"
      cert_thumbprint     = "5662AD9653AF2C8A3FC00043F7EC150F2641C39D"
      cert_valid_from     = "2024-08-03"
      cert_valid_to       = "2025-08-01"

      country             = "DK"
      state               = "Region of Southern Denmark"
      locality            = "Fredericia"
      email               = "???"
      rdn_serial_number   = "39884720"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "77:12:f7:72:c4:4d:33:60:d6:35:86:3e:74:14:f3:4b"
      )
}
