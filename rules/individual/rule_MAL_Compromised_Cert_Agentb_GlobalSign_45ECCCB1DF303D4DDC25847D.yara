import "pe"

rule MAL_Compromised_Cert_Agentb_GlobalSign_45ECCCB1DF303D4DDC25847D {
   meta:
      description         = "Detects Agentb with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-13"
      version             = "1.0"

      hash                = "09eddd2406db01b4f1999f7529b3175df555fbcb7f26f8a90e9ec3448a14f454"
      malware             = "Agentb"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "TC SOYUZPLIT LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "45:ec:cc:b1:df:30:3d:4d:dc:25:84:7d"
      cert_thumbprint     = "D8B04523D86270CE8BF8A834D7DA22829F1A8D16"
      cert_valid_from     = "2025-02-13"
      cert_valid_to       = "2026-01-23"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "5157746066187"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "45:ec:cc:b1:df:30:3d:4d:dc:25:84:7d"
      )
}
