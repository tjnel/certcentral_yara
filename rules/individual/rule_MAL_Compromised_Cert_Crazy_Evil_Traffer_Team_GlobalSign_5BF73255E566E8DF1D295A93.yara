import "pe"

rule MAL_Compromised_Cert_Crazy_Evil_Traffer_Team_GlobalSign_5BF73255E566E8DF1D295A93 {
   meta:
      description         = "Detects Crazy Evil Traffer Team with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-13"
      version             = "1.0"

      hash                = "f1c2dd0c85d6605d7d61989661f785c00ff4a8ade3362ccdecf2c80a8f86de13"
      malware             = "Crazy Evil Traffer Team"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "Morning Leap & Cazo Electronics Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5b:f7:32:55:e5:66:e8:df:1d:29:5a:93"
      cert_thumbprint     = "DAE0D3EDDBE1F96261E1B561915BACE5B215F2ED"
      cert_valid_from     = "2025-03-13"
      cert_valid_to       = "2026-03-14"

      country             = "CN"
      state               = "Hebei"
      locality            = "Cangzhou"
      email               = "???"
      rdn_serial_number   = "91130922MA0G8AN920"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5b:f7:32:55:e5:66:e8:df:1d:29:5a:93"
      )
}
