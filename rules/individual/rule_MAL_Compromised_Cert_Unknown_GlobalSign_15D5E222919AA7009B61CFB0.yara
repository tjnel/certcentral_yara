import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_15D5E222919AA7009B61CFB0 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-07"
      version             = "1.0"

      hash                = "499dfe9165ebd558b573539a7c25f5c8ddbcced110b9d4cfdc266d326c940902"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shanghai Star Channel Biological Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "15:d5:e2:22:91:9a:a7:00:9b:61:cf:b0"
      cert_thumbprint     = "8279347A7918F54AC2CB20CAA3A997F5A7793CAC"
      cert_valid_from     = "2024-06-07"
      cert_valid_to       = "2025-06-08"

      country             = "CN"
      state               = "Shanghai"
      locality            = "Shanghai"
      email               = "???"
      rdn_serial_number   = "91310113MA1GMAT805"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "15:d5:e2:22:91:9a:a7:00:9b:61:cf:b0"
      )
}
