import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Sectigo_00B73548A6B5D65D00DFE76D49555D4DD1 {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-13"
      version             = "1.0"

      hash                = "7e9078fd8654028df65a47ccba18f25fd3bdfb1b7716495e063b95b9ff1fd06e"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Yiwu Liangheng Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:b7:35:48:a6:b5:d6:5d:00:df:e7:6d:49:55:5d:4d:d1"
      cert_thumbprint     = "F6DCDE1F48BA82AEC496DFF289537FFFE8F73008"
      cert_valid_from     = "2025-08-13"
      cert_valid_to       = "2028-08-12"

      country             = "CN"
      state               = "浙江省"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:b7:35:48:a6:b5:d6:5d:00:df:e7:6d:49:55:5d:4d:d1"
      )
}
