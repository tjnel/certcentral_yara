import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_GlobalSign_3F4C9B98FD5FBBFF44B8A012 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-13"
      version             = "1.0"

      hash                = "d263dc3cef339b6192232d835e4f20049a3f88531453ffa078d3bcea9b40febe"
      malware             = "NetSupport RAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC SKT SERVICE"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3f:4c:9b:98:fd:5f:bb:ff:44:b8:a0:12"
      cert_thumbprint     = "E7873FBED486092FAA43DF45D79E33CA2115284B"
      cert_valid_from     = "2025-12-13"
      cert_valid_to       = "2026-03-27"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1187746507850"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3f:4c:9b:98:fd:5f:bb:ff:44:b8:a0:12"
      )
}
