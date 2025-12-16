import "pe"

rule MAL_Compromised_Cert_D3F_ckLoader_GlobalSign_6EF9C1E8363D7C4C98C274C1 {
   meta:
      description         = "Detects D3F@ckLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-14"
      version             = "1.0"

      hash                = "3a157e439b3c4601463022f2165358ebfc9f80dd2d33c9a6afc5467c3f858567"
      malware             = "D3F@ckLoader"
      malware_type        = "Loader"
      malware_notes       = "This malware as sold was part of a service: it included both the loader and a code-signing certificate. See this for more details: https://www.esentire.com/blog/exploring-the-d3f-ck-malware-as-a-service-loader"

      signer              = "LLC Laion"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "6e:f9:c1:e8:36:3d:7c:4c:98:c2:74:c1"
      cert_thumbprint     = "67F7B364DB53E7B45EF28E9AD16FA16D7625EFF1"
      cert_valid_from     = "2024-06-14"
      cert_valid_to       = "2025-06-15"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1237700901569"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "6e:f9:c1:e8:36:3d:7c:4c:98:c2:74:c1"
      )
}
