import "pe"

rule MAL_Compromised_Cert_Softwarecloud_SSL_com_34D3F03F4594AF3324E51BF37535AFE8 {
   meta:
      description         = "Detects Softwarecloud with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-21"
      version             = "1.0"

      hash                = "6ac730c099d7ff078c39fe3147ba51e52c22a9f99a8979c7f013509de732244c"
      malware             = "Softwarecloud"
      malware_type        = "Unknown"
      malware_notes       = "This malware is part of a campaign of inauthentic software. More research is likely needed: https://x.com/andrewdanis/status/1919585650413629680?s=20"

      signer              = "Callicrates GmbH"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "34:d3:f0:3f:45:94:af:33:24:e5:1b:f3:75:35:af:e8"
      cert_thumbprint     = "22AD904CB0DCE63662E8A2C245C7EFE82893612A"
      cert_valid_from     = "2025-05-21"
      cert_valid_to       = "2026-05-21"

      country             = "AT"
      state               = "Vienna"
      locality            = "Vienna"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "34:d3:f0:3f:45:94:af:33:24:e5:1b:f3:75:35:af:e8"
      )
}
