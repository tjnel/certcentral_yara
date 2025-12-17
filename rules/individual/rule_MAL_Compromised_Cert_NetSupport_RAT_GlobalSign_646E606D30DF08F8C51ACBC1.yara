import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_GlobalSign_646E606D30DF08F8C51ACBC1 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-11"
      version             = "1.0"

      hash                = "0bb16506d1f5c422644435a7dafd379c96f136f4e68703a45266066694ede59e"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Changchun Bapco Technology Development Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "64:6e:60:6d:30:df:08:f8:c5:1a:cb:c1"
      cert_thumbprint     = "E03C2FF39F7E304C2737AEEB68182381277172B8"
      cert_valid_from     = "2024-06-11"
      cert_valid_to       = "2025-06-12"

      country             = "CN"
      state               = "Jilin"
      locality            = "Changchun"
      email               = "???"
      rdn_serial_number   = "91220105MA145FUX1P"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "64:6e:60:6d:30:df:08:f8:c5:1a:cb:c1"
      )
}
