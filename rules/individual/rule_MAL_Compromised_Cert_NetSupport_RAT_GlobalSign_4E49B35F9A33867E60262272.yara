import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_GlobalSign_4E49B35F9A33867E60262272 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-25"
      version             = "1.0"

      hash                = "99da08e1e26390610c2431c8237a0fa2caf5e9c781db06170851f151ed3d65bf"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "LLC Capital Garant"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "4e:49:b3:5f:9a:33:86:7e:60:26:22:72"
      cert_thumbprint     = "0958F6DEE35AE2DD4601F43631CB0095E55781D4"
      cert_valid_from     = "2025-07-25"
      cert_valid_to       = "2026-07-12"

      country             = "RU"
      state               = "Saint Petersburg"
      locality            = "Saint Petersburg"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "4e:49:b3:5f:9a:33:86:7e:60:26:22:72"
      )
}
