import "pe"

rule MAL_Compromised_Cert_Rusty_Traffer_GlobalSign_42A8D0AF488FDE4A8C95A2FC {
   meta:
      description         = "Detects Rusty Traffer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-26"
      version             = "1.0"

      hash                = "c7f2c2b2c0f2c6cfad2b8e23c5ab3eea6545c93614491f79ea328e5f3622e3b4"
      malware             = "Rusty Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "NOBIS LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "42:a8:d0:af:48:8f:de:4a:8c:95:a2:fc"
      cert_thumbprint     = "7CE89347A41A1DA066EACD8FA06645495F12D973"
      cert_valid_from     = "2025-02-26"
      cert_valid_to       = "2026-02-18"

      country             = "RU"
      state               = "Moscow Oblast"
      locality            = "Vidnoye"
      email               = "???"
      rdn_serial_number   = "1105003003390"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "42:a8:d0:af:48:8f:de:4a:8c:95:a2:fc"
      )
}
