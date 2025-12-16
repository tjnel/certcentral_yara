import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_GlobalSign_10C11E651FF7C708C318664F {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-16"
      version             = "1.0"

      hash                = "8ce0c633472eeb3259a48bdc0997dfdbf3911d07d30f43e8bc08ad406c9a4020"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "Hebei YiLuoDuo Import and Export Trade Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "10:c1:1e:65:1f:f7:c7:08:c3:18:66:4f"
      cert_thumbprint     = "7292EEDE289822C228606F1C8C18E7404E59E33A"
      cert_valid_from     = "2024-05-16"
      cert_valid_to       = "2025-05-17"

      country             = "CN"
      state               = "Hebei"
      locality            = "Shijiazhuang"
      email               = "???"
      rdn_serial_number   = "91130108MA07PFJ284"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "10:c1:1e:65:1f:f7:c7:08:c3:18:66:4f"
      )
}
