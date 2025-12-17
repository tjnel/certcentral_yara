import "pe"

rule MAL_Compromised_Cert_Lazarus_Sectigo_029BF7E1CB09FE277564BD27C267DE5A {
   meta:
      description         = "Detects Lazarus with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-11-24"
      version             = "1.0"

      hash                = "829eceee720b0a3e505efbd3262c387b92abdf46183d51a50489e2b157dac3b1"
      malware             = "Lazarus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SAMOYAJ LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "02:9b:f7:e1:cb:09:fe:27:75:64:bd:27:c2:67:de:5a"
      cert_thumbprint     = "F916A11E205B1D456FC9B1004B997378EAD71C58"
      cert_valid_from     = "2021-11-24"
      cert_valid_to       = "2022-11-24"

      country             = "GB"
      state               = "West Yorkshire"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "02:9b:f7:e1:cb:09:fe:27:75:64:bd:27:c2:67:de:5a"
      )
}
