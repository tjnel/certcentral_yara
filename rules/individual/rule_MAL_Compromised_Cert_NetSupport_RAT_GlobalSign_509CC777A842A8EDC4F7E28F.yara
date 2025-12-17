import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_GlobalSign_509CC777A842A8EDC4F7E28F {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-22"
      version             = "1.0"

      hash                = "ffed8cd32c68d30a9e0f3d4484084982ca92667a99ade3bf32d58125dcd15f5e"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "RIMMA LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "50:9c:c7:77:a8:42:a8:ed:c4:f7:e2:8f"
      cert_thumbprint     = "50316559E0E132F84D6FE3572C0F8360E41B10BB"
      cert_valid_from     = "2025-09-22"
      cert_valid_to       = "2025-12-05"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "50:9c:c7:77:a8:42:a8:ed:c4:f7:e2:8f"
      )
}
