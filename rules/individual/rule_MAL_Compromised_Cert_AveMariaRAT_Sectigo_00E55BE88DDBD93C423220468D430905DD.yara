import "pe"

rule MAL_Compromised_Cert_AveMariaRAT_Sectigo_00E55BE88DDBD93C423220468D430905DD {
   meta:
      description         = "Detects AveMariaRAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-11-24"
      version             = "1.0"

      hash                = "051400edf4aae2a1041743c1b12740a9e03cf51b6f9491e7e08138640dcd0db6"
      malware             = "AveMariaRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "VALVE ACTUATION LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:e5:5b:e8:8d:db:d9:3c:42:32:20:46:8d:43:09:05:dd"
      cert_thumbprint     = "C1ED7E3E0F21C645CE3DC12ADB37D24D7754F02F"
      cert_valid_from     = "2021-11-24"
      cert_valid_to       = "2022-11-24"

      country             = "GB"
      state               = "Nottinghamshire"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:e5:5b:e8:8d:db:d9:3c:42:32:20:46:8d:43:09:05:dd"
      )
}
