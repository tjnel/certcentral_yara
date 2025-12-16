import "pe"

rule MAL_Compromised_Cert_Crazy_Evil_Traffer_Team_GlobalSign_290D9001839754E3D50E5295 {
   meta:
      description         = "Detects Crazy Evil Traffer Team with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-17"
      version             = "1.0"

      hash                = "b678637aa881360593e3ec949a55e0536506f50f78b0bfa0909029f3548b8998"
      malware             = "Crazy Evil Traffer Team"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "JSC Unicom"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "29:0d:90:01:83:97:54:e3:d5:0e:52:95"
      cert_thumbprint     = "B9F46FFC12D9D430729445D643730A6D67AFCF08"
      cert_valid_from     = "2025-04-17"
      cert_valid_to       = "2026-04-18"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1087746687797"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "29:0d:90:01:83:97:54:e3:d5:0e:52:95"
      )
}
