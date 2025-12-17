import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Go_Daddy_00DBC03CA7E6AE6DB6 {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Go Daddy)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-09-23"
      version             = "1.0"

      hash                = "eb6febe456a9d3d5066cc0f746789c446f609d4df35b153760758f8b350fc3e4"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "SPIDER DEVELOPMENTS PTY LTD"
      cert_issuer_short   = "Go Daddy"
      cert_issuer         = "Go Daddy Secure Certificate Authority - G2"
      cert_serial         = "00:db:c0:3c:a7:e6:ae:6d:b6"
      cert_thumbprint     = "2F8D05E2B14B9F8C1271C92B8A2DE45C0DBADFB1"
      cert_valid_from     = "2020-09-23"
      cert_valid_to       = "2022-09-22"

      country             = "AU"
      state               = "Western Australia"
      locality            = "West Perth"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Go Daddy Secure Certificate Authority - G2" and
         sig.serial == "00:db:c0:3c:a7:e6:ae:6d:b6"
      )
}
