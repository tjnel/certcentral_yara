import "pe"

rule MAL_Compromised_Cert_Crazy_Evil_Traffer_Team_GlobalSign_010A8D74E727BB24A47EA7FC {
   meta:
      description         = "Detects Crazy Evil Traffer Team with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-09"
      version             = "1.0"

      hash                = "3f666cd864799da19cda48cd1caa5148965ab3fe31ce438d2be087802c8f04e1"
      malware             = "Crazy Evil Traffer Team"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "Fengyan Trading Co., Ltd. In Yanhu District, Yuncheng City"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "01:0a:8d:74:e7:27:bb:24:a4:7e:a7:fc"
      cert_thumbprint     = "50A290527E46E52A550F3C07A0F134C2FD356CE2"
      cert_valid_from     = "2025-05-09"
      cert_valid_to       = "2026-05-10"

      country             = "CN"
      state               = "Shanxi"
      locality            = "Yuncheng"
      email               = "???"
      rdn_serial_number   = "91140802MADALQC44B"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "01:0a:8d:74:e7:27:bb:24:a4:7e:a7:fc"
      )
}
