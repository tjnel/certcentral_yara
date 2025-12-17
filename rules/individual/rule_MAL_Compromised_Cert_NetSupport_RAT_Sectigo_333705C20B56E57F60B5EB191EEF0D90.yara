import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_Sectigo_333705C20B56E57F60B5EB191EEF0D90 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-09-10"
      version             = "1.0"

      hash                = "2bc947ba8cdd40b69936dbe365357961bdc99eb38fe999d9b906d10c5325a10e"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "TASK Holding ApS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "33:37:05:c2:0b:56:e5:7f:60:b5:eb:19:1e:ef:0d:90"
      cert_thumbprint     = "44F0F77D8B649579FA6F88AE9FA4B4206B90B120"
      cert_valid_from     = "2021-09-10"
      cert_valid_to       = "2022-09-11"

      country             = "DK"
      state               = "Hovedstaden"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "33:37:05:c2:0b:56:e5:7f:60:b5:eb:19:1e:ef:0d:90"
      )
}
