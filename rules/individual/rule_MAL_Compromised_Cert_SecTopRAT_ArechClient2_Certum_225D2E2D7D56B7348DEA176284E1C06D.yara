import "pe"

rule MAL_Compromised_Cert_SecTopRAT_ArechClient2_Certum_225D2E2D7D56B7348DEA176284E1C06D {
   meta:
      description         = "Detects SecTopRAT,ArechClient2 with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-04"
      version             = "1.0"

      hash                = "4f1c363f78622203140d886f70ac33ed626ff870d389be55c5d212f5113a6eaa"
      malware             = "SecTopRAT,ArechClient2"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "BVD Software Inc."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "22:5d:2e:2d:7d:56:b7:34:8d:ea:17:62:84:e1:c0:6d"
      cert_thumbprint     = "13B86D9114768942433F2E01896283792CBDB205"
      cert_valid_from     = "2024-07-04"
      cert_valid_to       = "2025-07-04"

      country             = "CA"
      state               = "???"
      locality            = "Richmond Hill"
      email               = "???"
      rdn_serial_number   = "952412-6"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "22:5d:2e:2d:7d:56:b7:34:8d:ea:17:62:84:e1:c0:6d"
      )
}
