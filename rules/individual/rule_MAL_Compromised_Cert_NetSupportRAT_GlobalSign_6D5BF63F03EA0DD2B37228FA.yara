import "pe"

rule MAL_Compromised_Cert_NetSupportRAT_GlobalSign_6D5BF63F03EA0DD2B37228FA {
   meta:
      description         = "Detects NetSupportRAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-17"
      version             = "1.0"

      hash                = "9fb97ddbe7875a6162a0f6803c1e1679d6e8797c473b676f9d51ca77691abfeb"
      malware             = "NetSupportRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "SIAFU LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "6d:5b:f6:3f:03:ea:0d:d2:b3:72:28:fa"
      cert_thumbprint     = "B0D91034DAB6E6C6FA1ECDA42975D4AB03646CA7"
      cert_valid_from     = "2025-02-17"
      cert_valid_to       = "2026-02-18"

      country             = "KE"
      state               = "Nairobi"
      locality            = "Nairobi"
      email               = "???"
      rdn_serial_number   = "C.10158"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "6d:5b:f6:3f:03:ea:0d:d2:b3:72:28:fa"
      )
}
