import "pe"

rule MAL_Compromised_Cert_TrojanNetExtender_GlobalSign_1CB4DC9635AA0A7F6D3A985B {
   meta:
      description         = "Detects TrojanNetExtender with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-21"
      version             = "1.0"

      hash                = "d883c067f060e0f9643667d83ff7bc55a218151df600b18991b50a4ead513364"
      malware             = "TrojanNetExtender"
      malware_type        = "Trojan"
      malware_notes       = "This was a trojanized VPN client pushed through advertising. Per SonicWall, the malware would send the user's configuration to the attacker : https://www.sonicwall.com/blog/threat-actors-modify-and-re-create-commercial-software-to-steal-users-information"

      signer              = "CITYLIGHT MEDIA PRIVATE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "1c:b4:dc:96:35:aa:0a:7f:6d:3a:98:5b"
      cert_thumbprint     = "A01D612409D9839CCCD24174D31A183C6913EBB6"
      cert_valid_from     = "2025-05-21"
      cert_valid_to       = "2026-05-22"

      country             = "IN"
      state               = "Rajasthan"
      locality            = "Jaipur"
      email               = "???"
      rdn_serial_number   = "U74999RJ2020PTC072674"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "1c:b4:dc:96:35:aa:0a:7f:6d:3a:98:5b"
      )
}
