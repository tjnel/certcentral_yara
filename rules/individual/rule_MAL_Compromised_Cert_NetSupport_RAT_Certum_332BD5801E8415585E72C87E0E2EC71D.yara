import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_Certum_332BD5801E8415585E72C87E0E2EC71D {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-09-08"
      version             = "1.0"

      hash                = "306a4acb51995d012cedf11eeae5e6cd9f41bf577dc5b6855a9df61ce843bc67"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Elite Marketing Strategies, Inc."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "33:2b:d5:80:1e:84:15:58:5e:72:c8:7e:0e:2e:c7:1d"
      cert_thumbprint     = "A9709D8C4C121682DC67DF6D9C16FB79694C6BCC"
      cert_valid_from     = "2022-09-08"
      cert_valid_to       = "2023-09-08"

      country             = "US"
      state               = "Wyoming"
      locality            = "Cheyenne"
      email               = "???"
      rdn_serial_number   = "2022-001126825"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "33:2b:d5:80:1e:84:15:58:5e:72:c8:7e:0e:2e:c7:1d"
      )
}
