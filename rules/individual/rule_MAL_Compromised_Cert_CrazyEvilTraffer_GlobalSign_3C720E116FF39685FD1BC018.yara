import "pe"

rule MAL_Compromised_Cert_CrazyEvilTraffer_GlobalSign_3C720E116FF39685FD1BC018 {
   meta:
      description         = "Detects CrazyEvilTraffer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-30"
      version             = "1.0"

      hash                = "7c5583fff213bd93237b110c274a7ceb8063dd7ee1d0b4fd38351e2975be5cee"
      malware             = "CrazyEvilTraffer"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "AASIM MEDICARE PRIVATE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3c:72:0e:11:6f:f3:96:85:fd:1b:c0:18"
      cert_thumbprint     = "C51DF2A048F6E41B542A02BBC688884E4DE7011E"
      cert_valid_from     = "2025-06-30"
      cert_valid_to       = "2026-07-01"

      country             = "IN"
      state               = "Bihar"
      locality            = "Samastipur"
      email               = "karansn82@gmail.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3c:72:0e:11:6f:f3:96:85:fd:1b:c0:18"
      )
}
