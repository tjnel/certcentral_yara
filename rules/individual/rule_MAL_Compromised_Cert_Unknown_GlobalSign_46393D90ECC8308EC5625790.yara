import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_46393D90ECC8308EC5625790 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-22"
      version             = "1.0"

      hash                = "b4baeef3427073425583564818084425d8069919b6f45b994121c91c7c067d01"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SHINE YOUR GUTS (SMC-PRIVATE) LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "46:39:3d:90:ec:c8:30:8e:c5:62:57:90"
      cert_thumbprint     = "7894608DA0897059C0EBD03E4BA917A85579D3D9"
      cert_valid_from     = "2024-04-22"
      cert_valid_to       = "2025-04-23"

      country             = "PK"
      state               = "Punjab"
      locality            = "Lahore"
      email               = "gnazar423@gmail.com"
      rdn_serial_number   = "0146772"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "46:39:3d:90:ec:c8:30:8e:c5:62:57:90"
      )
}
