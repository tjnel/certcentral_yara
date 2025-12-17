import "pe"

rule MAL_Compromised_Cert_Traffer_GlobalSign_7FE807E8EDAF5EF32235D7C2 {
   meta:
      description         = "Detects Traffer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-03"
      version             = "1.0"

      hash                = "258f786dcb85b0d409d1da7ceced6384cca843036a1e648e191753695dd780cf"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MAKUENI AGENCIES LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7f:e8:07:e8:ed:af:5e:f3:22:35:d7:c2"
      cert_thumbprint     = "7784C34D3730124B89914C6A6BACDBB2A0939487"
      cert_valid_from     = "2025-02-03"
      cert_valid_to       = "2026-02-04"

      country             = "KE"
      state               = "Nairobi"
      locality            = "Nairobi"
      email               = "???"
      rdn_serial_number   = "CPR/2014/130160"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7f:e8:07:e8:ed:af:5e:f3:22:35:d7:c2"
      )
}
