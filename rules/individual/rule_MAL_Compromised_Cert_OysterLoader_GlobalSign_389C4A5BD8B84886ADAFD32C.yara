import "pe"

rule MAL_Compromised_Cert_OysterLoader_GlobalSign_389C4A5BD8B84886ADAFD32C {
   meta:
      description         = "Detects OysterLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-23"
      version             = "1.0"

      hash                = "6b3e43c17908ee10944c2453983444da0f0242eac47534d0fb6111a03df0c66c"
      malware             = "OysterLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "LLC Stroy-Vertical"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "38:9c:4a:5b:d8:b8:48:86:ad:af:d3:2c"
      cert_thumbprint     = "0A0D669E3899C3E8CF8ADEFB56B827DE0F052876"
      cert_valid_from     = "2025-04-23"
      cert_valid_to       = "2026-04-24"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "38:9c:4a:5b:d8:b8:48:86:ad:af:d3:2c"
      )
}
