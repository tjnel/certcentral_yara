import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_GlobalSign_05BF822AC83E8A6BC0277A41 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-13"
      version             = "1.0"

      hash                = "233d0e0483c769061d61201b6b06ab8c9460ad40ec7e70384ce54c8c258fa5e5"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "LLC Extrastroy"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "05:bf:82:2a:c8:3e:8a:6b:c0:27:7a:41"
      cert_thumbprint     = "C699047F344062CCF95578BF470DD08BFBDD7ECB"
      cert_valid_from     = "2025-06-13"
      cert_valid_to       = "2026-06-14"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1187746693640"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "05:bf:82:2a:c8:3e:8a:6b:c0:27:7a:41"
      )
}
