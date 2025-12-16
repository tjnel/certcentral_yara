import "pe"

rule MAL_Compromised_Cert_PayDayLoader_GlobalSign_4E8CCC13DF95117058746F21 {
   meta:
      description         = "Detects PayDayLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-01"
      version             = "1.0"

      hash                = "c3f9c300ca939a51d599114246beb08afb473bff565438994e9e1b457dbf5492"
      malware             = "PayDayLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC KomService"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "4e:8c:cc:13:df:95:11:70:58:74:6f:21"
      cert_thumbprint     = "531C408CC578CD47B2B012AF2DE61698F657D0A9"
      cert_valid_from     = "2025-05-01"
      cert_valid_to       = "2026-05-02"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "4e:8c:cc:13:df:95:11:70:58:74:6f:21"
      )
}
