import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Certum_038FC745523B41B40D653B83AA381B80 {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-11-23"
      version             = "1.0"

      hash                = "e844577efbd9d78da8849997491807f1f9d3ae7d7f010363e2c25c6de2687eba"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "OOO Optima"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing CA SHA2"
      cert_serial         = "03:8f:c7:45:52:3b:41:b4:0d:65:3b:83:aa:38:1b:80"
      cert_thumbprint     = "05124A4A385B4B2D7A9B58D1C3AD7F2A84E7B0AF"
      cert_valid_from     = "2020-11-23"
      cert_valid_to       = "2021-11-23"

      country             = "RU"
      state               = "???"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1167746706687"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing CA SHA2" and
         sig.serial == "03:8f:c7:45:52:3b:41:b4:0d:65:3b:83:aa:38:1b:80"
      )
}
