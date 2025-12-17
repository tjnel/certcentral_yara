import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_GlobalSign_2F94A1516E8A182B148F994A {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-09"
      version             = "1.0"

      hash                = "6b8013ce46162259cdfd2e9c74e43ec72209b5b96e2cc5e051a17687da42e35d"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "ООО НЕВА КЕРАМИКС"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "2f:94:a1:51:6e:8a:18:2b:14:8f:99:4a"
      cert_thumbprint     = "4645E8244D0240FED60A8923999340F10F363EA5"
      cert_valid_from     = "2024-12-09"
      cert_valid_to       = "2025-12-10"

      country             = "RU"
      state               = "Санкт-Петербург"
      locality            = "Санкт-Петербург"
      email               = "Clearnds2011@mail.ru"
      rdn_serial_number   = "1147847357217"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "2f:94:a1:51:6e:8a:18:2b:14:8f:99:4a"
      )
}
