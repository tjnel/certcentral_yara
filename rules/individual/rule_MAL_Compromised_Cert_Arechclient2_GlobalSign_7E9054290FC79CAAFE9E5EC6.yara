import "pe"

rule MAL_Compromised_Cert_Arechclient2_GlobalSign_7E9054290FC79CAAFE9E5EC6 {
   meta:
      description         = "Detects Arechclient2 with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-06"
      version             = "1.0"

      hash                = "abb3b093bea395593eb63864ae4333d98c5da4a585cdd4a170b23836077ae100"
      malware             = "Arechclient2"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "INTENDER LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7e:90:54:29:0f:c7:9c:aa:fe:9e:5e:c6"
      cert_thumbprint     = "E6151899B943D917C49F32B9AE3DF769793F52FD"
      cert_valid_from     = "2025-03-06"
      cert_valid_to       = "2026-03-07"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1247700182311"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7e:90:54:29:0f:c7:9c:aa:fe:9e:5e:c6"
      )
}
