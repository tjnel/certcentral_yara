import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_GlobalSign_34A8A2E38E640CDA8D8599B7 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-04"
      version             = "1.0"

      hash                = "bd97ecf1a07fbc5cc1cfcbdfb73368e01f14c3e8abe061f73543627bddd9eb6d"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "STK LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "34:a8:a2:e3:8e:64:0c:da:8d:85:99:b7"
      cert_thumbprint     = "E105FAF738FD342D18D180B32E952599FE2E3333"
      cert_valid_from     = "2025-07-04"
      cert_valid_to       = "2026-07-05"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1187746040228"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "34:a8:a2:e3:8e:64:0c:da:8d:85:99:b7"
      )
}
