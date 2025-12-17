import "pe"

rule MAL_Compromised_Cert_D3F_ckLoader_SSL_com_48095E8078225651A5346BE4226D5A74 {
   meta:
      description         = "Detects D3F@ckLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-03"
      version             = "1.0"

      hash                = "277a9093786d4cb2dd267ea6e15eaeb22a568bdc72c4ea6d1aa9b355a190d812"
      malware             = "D3F@ckLoader"
      malware_type        = "Loader"
      malware_notes       = "This malware as sold was part of a service: it included both the loader and a code-signing certificate. See this for more details: https://www.esentire.com/blog/exploring-the-d3f-ck-malware-as-a-service-loader"

      signer              = "Eleventh Edition Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "48:09:5e:80:78:22:56:51:a5:34:6b:e4:22:6d:5a:74"
      cert_thumbprint     = "8DBB4A47E95F34E8E685BD4B7664D61D0863B278"
      cert_valid_from     = "2024-05-03"
      cert_valid_to       = "2025-05-03"

      country             = "GB"
      state               = "Scotland"
      locality            = "Glasgow"
      email               = "???"
      rdn_serial_number   = "SC646989"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "48:09:5e:80:78:22:56:51:a5:34:6b:e4:22:6d:5a:74"
      )
}
