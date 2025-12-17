import "pe"

rule MAL_Compromised_Cert_VileRAT_GlobalSign_5EDBCCFBE91A2DF04D7CC795 {
   meta:
      description         = "Detects VileRAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-08-07"
      version             = "1.0"

      hash                = "21ae1d88e675c9a2d51a2f68beadf24a21c1b16f58fc042ff97ad8e52501300d"
      malware             = "VileRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "GLOSUB LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5e:db:cc:fb:e9:1a:2d:f0:4d:7c:c7:95"
      cert_thumbprint     = "365EE3CB9639107C7ABE51F1756ECA61D6904166"
      cert_valid_from     = "2023-08-07"
      cert_valid_to       = "2024-08-07"

      country             = "UA"
      state               = "Kyiv"
      locality            = "Kyiv"
      email               = "???"
      rdn_serial_number   = "42179512"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5e:db:cc:fb:e9:1a:2d:f0:4d:7c:c7:95"
      )
}
