import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_GlobalSign_3F639FE6C6390AE939EAA74E {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-21"
      version             = "1.0"

      hash                = "e6a4f2de6f4e37b2a25beeeefb60ecb5af8f204c6d42c46ee885dec38f313d36"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ChasingFire Dream Technologies Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3f:63:9f:e6:c6:39:0a:e9:39:ea:a7:4e"
      cert_thumbprint     = "81E43EF1CC71E144A9C01BCFA88C39126F9995BE"
      cert_valid_from     = "2025-03-21"
      cert_valid_to       = "2026-03-22"

      country             = "CN"
      state               = "Hubei"
      locality            = "Wuhan"
      email               = "???"
      rdn_serial_number   = "91420115MA4L020L06"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3f:63:9f:e6:c6:39:0a:e9:39:ea:a7:4e"
      )
}
