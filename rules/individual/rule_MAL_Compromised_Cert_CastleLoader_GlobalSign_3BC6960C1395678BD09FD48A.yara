import "pe"

rule MAL_Compromised_Cert_CastleLoader_GlobalSign_3BC6960C1395678BD09FD48A {
   meta:
      description         = "Detects CastleLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-02"
      version             = "1.0"

      hash                = "977d7959330af8cb27a5dba1b96cb8ecd8b6c48ec809516465d6ada057fcfcd6"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "IMAGINATION369 CO., LTD."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3b:c6:96:0c:13:95:67:8b:d0:9f:d4:8a"
      cert_thumbprint     = "7A863A28FF1AE9327CDC2AE901FF0361F35A28F2"
      cert_valid_from     = "2025-12-02"
      cert_valid_to       = "2026-12-03"

      country             = "TH"
      state               = "Chonburi"
      locality            = "Bang Lamung"
      email               = "???"
      rdn_serial_number   = "0205566032476"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3b:c6:96:0c:13:95:67:8b:d0:9f:d4:8a"
      )
}
