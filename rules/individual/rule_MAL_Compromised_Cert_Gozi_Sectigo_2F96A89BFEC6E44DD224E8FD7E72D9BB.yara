import "pe"

rule MAL_Compromised_Cert_Gozi_Sectigo_2F96A89BFEC6E44DD224E8FD7E72D9BB {
   meta:
      description         = "Detects Gozi with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-07-06"
      version             = "1.0"

      hash                = "54de1f2c26a63a8f6b7f8d5de99f8ebd4093959ab07f027db1985d0652258736"
      malware             = "Gozi"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "NAILS UNLIMITED LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "2f:96:a8:9b:fe:c6:e4:4d:d2:24:e8:fd:7e:72:d9:bb"
      cert_thumbprint     = "CA69087AAAA087346202AD16228337130511C4C5"
      cert_valid_from     = "2021-07-06"
      cert_valid_to       = "2022-07-06"

      country             = "GB"
      state               = "Dorset"
      locality            = "DORCHESTER"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "2f:96:a8:9b:fe:c6:e4:4d:d2:24:e8:fd:7e:72:d9:bb"
      )
}
