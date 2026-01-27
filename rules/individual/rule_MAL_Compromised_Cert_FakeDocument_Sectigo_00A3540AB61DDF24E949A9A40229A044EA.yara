import "pe"

rule MAL_Compromised_Cert_FakeDocument_Sectigo_00A3540AB61DDF24E949A9A40229A044EA {
   meta:
      description         = "Detects FakeDocument with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-09"
      version             = "1.0"

      hash                = "37d154eb57de4a123528d53a6cc829da2ddf64532e52048a07fc569076ec6783"
      malware             = "FakeDocument"
      malware_type        = "Unknown"
      malware_notes       = "Malicious executables posing as fake documents targeting Brazilian individuals"

      signer              = "Auto Posto Silvestre Comercio de Combustiveis LTDA"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:a3:54:0a:b6:1d:df:24:e9:49:a9:a4:02:29:a0:44:ea"
      cert_thumbprint     = "1118EF0260D158A0B4F787F714CFB21AA354882C"
      cert_valid_from     = "2025-12-09"
      cert_valid_to       = "2026-12-09"

      country             = "BR"
      state               = "Rondônia"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "07.939.258/0001-05"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:a3:54:0a:b6:1d:df:24:e9:49:a9:a4:02:29:a0:44:ea"
      )
}
