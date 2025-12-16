import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_DigiCert_016558F3759AB455D5497251C51FF8F6 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2019-07-01"
      version             = "1.0"

      hash                = "7a5f2afe726768008f80860aa992e56e01cb609d6a0510348a528182ae4ad8d1"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "GetScatter Ltd."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert EV Code Signing CA (SHA2)"
      cert_serial         = "01:65:58:f3:75:9a:b4:55:d5:49:72:51:c5:1f:f8:f6"
      cert_thumbprint     = "31F52C1E030737D8BB0DCF6E3B3EC25D030396AF"
      cert_valid_from     = "2019-07-01"
      cert_valid_to       = "2022-07-06"

      country             = "MT"
      state               = "???"
      locality            = "Sliema"
      email               = "???"
      rdn_serial_number   = "C 89452"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert EV Code Signing CA (SHA2)" and
         sig.serial == "01:65:58:f3:75:9a:b4:55:d5:49:72:51:c5:1f:f8:f6"
      )
}
