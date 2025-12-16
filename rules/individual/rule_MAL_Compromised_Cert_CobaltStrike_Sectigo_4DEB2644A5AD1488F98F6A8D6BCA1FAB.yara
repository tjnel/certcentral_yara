import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Sectigo_4DEB2644A5AD1488F98F6A8D6BCA1FAB {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-10-05"
      version             = "1.0"

      hash                = "ede4978afd488eb4ab66e0270c1baadd8f7be1cd1f29bf969039c804148b0a56"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "coolschool"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "4d:eb:26:44:a5:ad:14:88:f9:8f:6a:8d:6b:ca:1f:ab"
      cert_thumbprint     = "B8818B7BB5F4E617E451F43196BFEABE6A8B9792"
      cert_valid_from     = "2022-10-05"
      cert_valid_to       = "2024-10-04"

      country             = "KR"
      state               = "Gyeonggi-do"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "4d:eb:26:44:a5:ad:14:88:f9:8f:6a:8d:6b:ca:1f:ab"
      )
}
