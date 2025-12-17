import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_00D38D292DC0439ADDA31068E2BC953FBE {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-05-10"
      version             = "1.0"

      hash                = "e0dc3f6155598058e276b1cb9da045ebc85e012cb4d706c17724f7afefc14058"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SORT CONSULTANCY LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:d3:8d:29:2d:c0:43:9a:dd:a3:10:68:e2:bc:95:3f:be"
      cert_thumbprint     = "6A56E83B550C647BC931D830800943A031EF02FF"
      cert_valid_from     = "2023-05-10"
      cert_valid_to       = "2024-05-10"

      country             = "GB"
      state               = "London"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:d3:8d:29:2d:c0:43:9a:dd:a3:10:68:e2:bc:95:3f:be"
      )
}
