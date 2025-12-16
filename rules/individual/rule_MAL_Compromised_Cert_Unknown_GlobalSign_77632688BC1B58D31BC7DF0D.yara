import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_77632688BC1B58D31BC7DF0D {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-14"
      version             = "1.0"

      hash                = "d9f9584f4f071be9c5cf418cae91423c51d53ecf9924ed39b42028d1314a2edc"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "AMARYLLIS SIGNAL LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "77:63:26:88:bc:1b:58:d3:1b:c7:df:0d"
      cert_thumbprint     = "02C4B0C7438F3AE718FFA47137B75151713F38EA"
      cert_valid_from     = "2025-01-14"
      cert_valid_to       = "2026-01-15"

      country             = "IL"
      state               = "Tel Aviv"
      locality            = "Tel Aviv"
      email               = "support@amarylisignal.com"
      rdn_serial_number   = "516891132"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "77:63:26:88:bc:1b:58:d3:1b:c7:df:0d"
      )
}
