import "pe"

rule MAL_Compromised_Cert_TrojanNetExtender_GlobalSign_2A687CED2A903566E1EA421C {
   meta:
      description         = "Detects TrojanNetExtender with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-06"
      version             = "1.0"

      hash                = "f7420e3210cec73b40102208bfeb6ea07be84c3fa7aa0f4cb809c68323e7c4c2"
      malware             = "TrojanNetExtender"
      malware_type        = "Trojan"
      malware_notes       = "This was a trojanized VPN client pushed through advertising. Per SonicWall, the malware would send the user's configuration to the attacker : https://www.sonicwall.com/blog/threat-actors-modify-and-re-create-commercial-software-to-steal-users-information"

      signer              = "MOHAN ENTERPRISES (RAJASTHAN) PVT LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "2a:68:7c:ed:2a:90:35:66:e1:ea:42:1c"
      cert_thumbprint     = "61E52B4F0312500CF72D6A14B304205C4F9CBB22"
      cert_valid_from     = "2025-08-06"
      cert_valid_to       = "2026-08-07"

      country             = "IN"
      state               = "Rajasthan"
      locality            = "Jaipur"
      email               = "mohanmohitrana@gmail.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "2a:68:7c:ed:2a:90:35:66:e1:ea:42:1c"
      )
}
