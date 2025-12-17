import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_GlobalSign_1BACADCA4264971772A3A024 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-14"
      version             = "1.0"

      hash                = "894266d5eddd19d343f354cfc235149bc4d85fbe2dea2544708a51b425ae8e34"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "VINA 68 INVESTMENT AND CONSTRUCTION JOINT STOCK COMPANY"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "1b:ac:ad:ca:42:64:97:17:72:a3:a0:24"
      cert_thumbprint     = "B50F0450A280825E1B08DEC289E1BE8936F3E90E"
      cert_valid_from     = "2025-04-14"
      cert_valid_to       = "2026-04-15"

      country             = "VN"
      state               = "Ha Nam"
      locality            = "Ha Nam"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "1b:ac:ad:ca:42:64:97:17:72:a3:a0:24"
      )
}
