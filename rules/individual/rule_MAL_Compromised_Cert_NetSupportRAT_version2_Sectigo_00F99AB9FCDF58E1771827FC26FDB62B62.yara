import "pe"

rule MAL_Compromised_Cert_NetSupportRAT_version2_Sectigo_00F99AB9FCDF58E1771827FC26FDB62B62 {
   meta:
      description         = "Detects NetSupportRAT_version2 with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-03-15"
      version             = "1.0"

      hash                = "fa3cb4f183ac3c1a7f6bc534d60f00468fa64ac0e91f1ffd83a89a4be2e70af7"
      malware             = "NetSupportRAT_version2"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Techsoft"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:f9:9a:b9:fc:df:58:e1:77:18:27:fc:26:fd:b6:2b:62"
      cert_thumbprint     = "C85DF3623274F9A30144BD72350B56C8DEE9AE76"
      cert_valid_from     = "2022-03-15"
      cert_valid_to       = "2025-03-15"

      country             = "IN"
      state               = "West Bengal"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:f9:9a:b9:fc:df:58:e1:77:18:27:fc:26:fd:b6:2b:62"
      )
}
