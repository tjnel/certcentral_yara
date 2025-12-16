import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_Certum_1B4174AA6AAF8921F344AAB138FF7F33 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-17"
      version             = "1.0"

      hash                = "0ec34875eaef4719aaea86ca037cb6fe89f897a1cbbdd01013e71637fa7e89e1"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Skilsure Software Limited"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "1b:41:74:aa:6a:af:89:21:f3:44:aa:b1:38:ff:7f:33"
      cert_thumbprint     = "E823FD216198C8647D78D83E9947918B68B0D27A"
      cert_valid_from     = "2024-06-17"
      cert_valid_to       = "2025-06-17"

      country             = "GB"
      state               = "???"
      locality            = "Milton Keynes"
      email               = "???"
      rdn_serial_number   = "13393128"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "1b:41:74:aa:6a:af:89:21:f3:44:aa:b1:38:ff:7f:33"
      )
}
