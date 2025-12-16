import "pe"

rule MAL_Compromised_Cert_D3F_ckLoader_GlobalSign_496D920DA43B2EBA710E135F {
   meta:
      description         = "Detects D3F@ckLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-01-23"
      version             = "1.0"

      hash                = "47470a874bcccca211f495e49db5b726f200ebd80fea3fc18b0ae7b059452fb6"
      malware             = "D3F@ckLoader"
      malware_type        = "Loader"
      malware_notes       = "This malware as sold was part of a service: it included both the loader and a code-signing certificate. See this for more details: https://www.esentire.com/blog/exploring-the-d3f-ck-malware-as-a-service-loader"

      signer              = "LLC Kama lubricant company"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "49:6d:92:0d:a4:3b:2e:ba:71:0e:13:5f"
      cert_thumbprint     = "886B9AF7AFAB9006FA8D14ACB69431372273B11F"
      cert_valid_from     = "2024-01-23"
      cert_valid_to       = "2025-01-23"

      country             = "RU"
      state               = "Republic of Tatarstan"
      locality            = "Biklyan"
      email               = "kamtranscomp@gmail.com"
      rdn_serial_number   = "1111682000176"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "49:6d:92:0d:a4:3b:2e:ba:71:0e:13:5f"
      )
}
