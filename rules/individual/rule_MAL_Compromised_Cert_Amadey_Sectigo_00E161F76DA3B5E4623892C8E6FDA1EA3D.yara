import "pe"

rule MAL_Compromised_Cert_Amadey_Sectigo_00E161F76DA3B5E4623892C8E6FDA1EA3D {
   meta:
      description         = "Detects Amadey with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-11-10"
      version             = "1.0"

      hash                = "9c3857a1bdbfe35ff17ca8bad9fb3af520a85ebc3d563ddc3855c38e11d9d07b"
      malware             = "Amadey"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "TGN Nedelica d.o.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:e1:61:f7:6d:a3:b5:e4:62:38:92:c8:e6:fd:a1:ea:3d"
      cert_thumbprint     = "DF5FBFBFD47875B580B150603DE240EAD9C7AD27"
      cert_valid_from     = "2020-11-10"
      cert_valid_to       = "2021-11-10"

      country             = "SI"
      state               = "???"
      locality            = "Turnišče"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:e1:61:f7:6d:a3:b5:e4:62:38:92:c8:e6:fd:a1:ea:3d"
      )
}
