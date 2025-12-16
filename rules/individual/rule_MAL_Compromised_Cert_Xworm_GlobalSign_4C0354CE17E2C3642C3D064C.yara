import "pe"

rule MAL_Compromised_Cert_Xworm_GlobalSign_4C0354CE17E2C3642C3D064C {
   meta:
      description         = "Detects Xworm with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-03-29"
      version             = "1.0"

      hash                = "b75dec6f19a3dec025862a0d6e7dd565ad49c327cd85c21d5135ccffef60e68f"
      malware             = "Xworm"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SyncFutureTec Company Limited"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 CodeSigning CA 2020"
      cert_serial         = "4c:03:54:ce:17:e2:c3:64:2c:3d:06:4c"
      cert_thumbprint     = "F9EAAB0F05BD38A251427A05F95386CA7CEDDCE8"
      cert_valid_from     = "2023-03-29"
      cert_valid_to       = "2025-03-29"

      country             = "CN"
      state               = "Jiangsu"
      locality            = "Nanjing"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 CodeSigning CA 2020" and
         sig.serial == "4c:03:54:ce:17:e2:c3:64:2c:3d:06:4c"
      )
}
