import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_Entrust_7010DF2D3C8A608E6CF69B79C7AD074E {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (Entrust)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-16"
      version             = "1.0"

      hash                = "524bfdb6922acdb543165762769df5bc7f6871751769c8923b213c3ac7ebd9ca"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Software Alliance ApS"
      cert_issuer_short   = "Entrust"
      cert_issuer         = "Entrust Extended Validation Code Signing CA - EVCS2"
      cert_serial         = "70:10:df:2d:3c:8a:60:8e:6c:f6:9b:79:c7:ad:07:4e"
      cert_thumbprint     = "27C2E54C69BCD81490999F1FC5E8DA18D2C1192B"
      cert_valid_from     = "2024-04-16"
      cert_valid_to       = "2025-04-16"

      country             = "DK"
      state               = "???"
      locality            = "Køge"
      email               = "???"
      rdn_serial_number   = "41660635"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Entrust Extended Validation Code Signing CA - EVCS2" and
         sig.serial == "70:10:df:2d:3c:8a:60:8e:6c:f6:9b:79:c7:ad:07:4e"
      )
}
