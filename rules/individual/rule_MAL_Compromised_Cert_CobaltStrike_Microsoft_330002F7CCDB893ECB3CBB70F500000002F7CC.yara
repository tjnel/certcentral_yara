import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Microsoft_330002F7CCDB893ECB3CBB70F500000002F7CC {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-13"
      version             = "1.0"

      hash                = "40183652b178bbb018185d714c0d023d81ce1943183eb7f563ad58fc2925cd88"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "志超 柴"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:02:f7:cc:db:89:3e:cb:3c:bb:70:f5:00:00:00:02:f7:cc"
      cert_thumbprint     = "F0373B67387A134DED91ECEE2A3D811C6F70F7DF"
      cert_valid_from     = "2025-03-13"
      cert_valid_to       = "2025-03-16"

      country             = "CN"
      state               = "???"
      locality            = "平南"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:02:f7:cc:db:89:3e:cb:3c:bb:70:f5:00:00:00:02:f7:cc"
      )
}
