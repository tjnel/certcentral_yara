import "pe"

rule MAL_Compromised_Cert_NetSupportRAT_GlobalSign_768D8B5A95252BFCF9BE0497 {
   meta:
      description         = "Detects NetSupportRAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-14"
      version             = "1.0"

      hash                = "ae45484a1881d55afae4952224c4a8352e1163a9fb57d095431711e5dccdcd18"
      malware             = "NetSupportRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Blockfi Ruinor Security Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "76:8d:8b:5a:95:25:2b:fc:f9:be:04:97"
      cert_thumbprint     = "4ACC7502C2F5106D47911AF8AB41B4C83D758DDE"
      cert_valid_from     = "2025-04-14"
      cert_valid_to       = "2026-04-15"

      country             = "CN"
      state               = "Shandong"
      locality            = "Jinan"
      email               = "???"
      rdn_serial_number   = "91370102307284861T"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "76:8d:8b:5a:95:25:2b:fc:f9:be:04:97"
      )
}
