import "pe"

rule MAL_Compromised_Cert_Latrodectus_stage2_GlobalSign_5FC7AB8E0CCD4838C82C1B61 {
   meta:
      description         = "Detects Latrodectus_stage2 with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-21"
      version             = "1.0"

      hash                = "765816c6e2c600c379014b4923f3d05eff5e91f46712da0fb21de99a6ca68021"
      malware             = "Latrodectus_stage2"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SKY SPACE TECHNO SOLUTIONS LLP"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5f:c7:ab:8e:0c:cd:48:38:c8:2c:1b:61"
      cert_thumbprint     = "F6DABE713EBA4A23A91BA440CFAE5732A23FCEA7"
      cert_valid_from     = "2025-07-21"
      cert_valid_to       = "2026-07-22"

      country             = "IN"
      state               = "Rajasthan"
      locality            = "Jaipur"
      email               = "teamskyspace@gmail.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5f:c7:ab:8e:0c:cd:48:38:c8:2c:1b:61"
      )
}
