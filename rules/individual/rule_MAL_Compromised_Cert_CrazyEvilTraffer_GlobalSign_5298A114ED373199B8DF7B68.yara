import "pe"

rule MAL_Compromised_Cert_CrazyEvilTraffer_GlobalSign_5298A114ED373199B8DF7B68 {
   meta:
      description         = "Detects CrazyEvilTraffer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-30"
      version             = "1.0"

      hash                = "1450b45187c0f485fad45496717be8e45dec1d4f619ee4294febeeb1d01fd66c"
      malware             = "CrazyEvilTraffer"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "SUNEX STONES PRIVATE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "52:98:a1:14:ed:37:31:99:b8:df:7b:68"
      cert_thumbprint     = "DD21129EBA5097150A8D0AAEAD2BC18746FAD52F"
      cert_valid_from     = "2025-05-30"
      cert_valid_to       = "2026-05-31"

      country             = "IN"
      state               = "Rajasthan"
      locality            = "Jaipur"
      email               = "anupsinghalrchem@gmail.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "52:98:a1:14:ed:37:31:99:b8:df:7b:68"
      )
}
