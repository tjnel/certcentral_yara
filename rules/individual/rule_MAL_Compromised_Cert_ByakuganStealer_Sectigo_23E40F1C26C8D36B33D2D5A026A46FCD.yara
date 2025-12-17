import "pe"

rule MAL_Compromised_Cert_ByakuganStealer_Sectigo_23E40F1C26C8D36B33D2D5A026A46FCD {
   meta:
      description         = "Detects ByakuganStealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-30"
      version             = "1.0"

      hash                = "3414b768b04cca4eb0a792110afa8b37186c109a47ad0290ffd46c0a0556d724"
      malware             = "ByakuganStealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Taiyuan Jiankang Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "23:e4:0f:1c:26:c8:d3:6b:33:d2:d5:a0:26:a4:6f:cd"
      cert_thumbprint     = "150167C4D465C74D4612D1E9C3510E02D032F9EA"
      cert_valid_from     = "2025-05-30"
      cert_valid_to       = "2026-05-30"

      country             = "CN"
      state               = "Shanxi Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91140106MA0M4WL26F"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "23:e4:0f:1c:26:c8:d3:6b:33:d2:d5:a0:26:a4:6f:cd"
      )
}
