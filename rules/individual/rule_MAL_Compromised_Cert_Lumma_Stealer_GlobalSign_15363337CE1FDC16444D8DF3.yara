import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_GlobalSign_15363337CE1FDC16444D8DF3 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-30"
      version             = "1.0"

      hash                = "c36338fbc2b1913fd79443706dedbc9f58adcfaf5af1dab06a592446e8f6dec6"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "MIKA LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "15:36:33:37:ce:1f:dc:16:44:4d:8d:f3"
      cert_thumbprint     = "59eaada4c4f218ed6a0c32fa15d463a3638d972e"
      cert_valid_from     = "2024-12-30"
      cert_valid_to       = "2025-12-31"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1247700784583"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "15:36:33:37:ce:1f:dc:16:44:4d:8d:f3"
      )
}
