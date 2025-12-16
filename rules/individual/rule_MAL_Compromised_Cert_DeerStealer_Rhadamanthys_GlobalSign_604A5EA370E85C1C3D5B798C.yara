import "pe"

rule MAL_Compromised_Cert_DeerStealer_Rhadamanthys_GlobalSign_604A5EA370E85C1C3D5B798C {
   meta:
      description         = "Detects DeerStealer, Rhadamanthys with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-25"
      version             = "1.0"

      hash                = "8a2590c9a17beff4632e5c888cee885f37901a664d21309b8b3b803462b160d7"
      malware             = "DeerStealer, Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "SONETEL LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "60:4a:5e:a3:70:e8:5c:1c:3d:5b:79:8c"
      cert_thumbprint     = "258a254e0a198ba8f40c1374729d46758c73135c033d0650f8c916ae69b15f43"
      cert_valid_from     = "2025-04-25"
      cert_valid_to       = "2026-03-20"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1247700047253"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "60:4a:5e:a3:70:e8:5c:1c:3d:5b:79:8c"
      )
}
