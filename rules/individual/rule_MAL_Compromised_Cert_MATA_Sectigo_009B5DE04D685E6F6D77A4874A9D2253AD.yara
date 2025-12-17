import "pe"

rule MAL_Compromised_Cert_MATA_Sectigo_009B5DE04D685E6F6D77A4874A9D2253AD {
   meta:
      description         = "Detects MATA with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-05-26"
      version             = "1.0"

      hash                = "07d272b607f082305ce7b1987bfa17dc967ab45c8cd89699bcdced34ea94e126"
      malware             = "MATA"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Nguyen thi minh"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:9b:5d:e0:4d:68:5e:6f:6d:77:a4:87:4a:9d:22:53:ad"
      cert_thumbprint     = "640A1EC65578C0920EB6B87B0E7705D6ED19A8D7"
      cert_valid_from     = "2022-05-26"
      cert_valid_to       = "2025-05-25"

      country             = "VN"
      state               = "Ninh Bình"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:9b:5d:e0:4d:68:5e:6f:6d:77:a4:87:4a:9d:22:53:ad"
      )
}
