import "pe"

rule MAL_Compromised_Cert_TrojanNetExtender_Microsoft_330003D0E5F6C1943A350E542100000003D0E5 {
   meta:
      description         = "Detects TrojanNetExtender with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-31"
      version             = "1.0"

      hash                = "9dbbe4cc89ef76681e435843bb77addc31349a30a5c13059bf0221ca2df75dee"
      malware             = "TrojanNetExtender"
      malware_type        = "Trojan"
      malware_notes       = "This was a trojanized VPN client pushed through advertising. Per SonicWall, the malware would send the user's configuration to the attacker : https://www.sonicwall.com/blog/threat-actors-modify-and-re-create-commercial-software-to-steal-users-information"

      signer              = "ACQUISITEX IMMOBILIER INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:03:d0:e5:f6:c1:94:3a:35:0e:54:21:00:00:00:03:d0:e5"
      cert_thumbprint     = "2872C9B66D5B115E531BA99BCC1D69DDD6872FFC"
      cert_valid_from     = "2025-07-31"
      cert_valid_to       = "2025-08-03"

      country             = "CA"
      state               = "Québec"
      locality            = "Montréal"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:03:d0:e5:f6:c1:94:3a:35:0e:54:21:00:00:00:03:d0:e5"
      )
}
