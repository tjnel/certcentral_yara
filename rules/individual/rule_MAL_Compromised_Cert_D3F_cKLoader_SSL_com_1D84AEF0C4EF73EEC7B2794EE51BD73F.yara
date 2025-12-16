import "pe"

rule MAL_Compromised_Cert_D3F_cKLoader_SSL_com_1D84AEF0C4EF73EEC7B2794EE51BD73F {
   meta:
      description         = "Detects D3F@cKLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-16"
      version             = "1.0"

      hash                = "e05f1e1b6bdef06093a10a0f08f7f2d8569a74d3f194112a5553feddb350ef79"
      malware             = "D3F@cKLoader"
      malware_type        = "Loader"
      malware_notes       = "This malware as sold was part of a service: it included both the loader and a code-signing certificate. See this for more details: https://www.esentire.com/blog/exploring-the-d3f-ck-malware-as-a-service-loader"

      signer              = "MAD PANDA LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "1d:84:ae:f0:c4:ef:73:ee:c7:b2:79:4e:e5:1b:d7:3f"
      cert_thumbprint     = "977A8331DCC4C0B37CA7EF6DB4B5B865DE16A989"
      cert_valid_from     = "2024-07-16"
      cert_valid_to       = "2025-07-16"

      country             = "GB"
      state               = "???"
      locality            = "Cobham"
      email               = "???"
      rdn_serial_number   = "12535189"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "1d:84:ae:f0:c4:ef:73:ee:c7:b2:79:4e:e5:1b:d7:3f"
      )
}
