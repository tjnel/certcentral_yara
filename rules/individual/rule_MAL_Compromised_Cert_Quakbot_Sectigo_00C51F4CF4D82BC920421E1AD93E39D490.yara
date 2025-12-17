import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00C51F4CF4D82BC920421E1AD93E39D490 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-02-12"
      version             = "1.0"

      hash                = "37e973699f119ce5a2047281aa6f52429bc15164abdfe110f3340ee02d4c21b5"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "CUT AHEAD LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:c5:1f:4c:f4:d8:2b:c9:20:42:1e:1a:d9:3e:39:d4:90"
      cert_thumbprint     = "93E82A7C73DBE0741BBC926A8CF17DFA5BBEA1E1"
      cert_valid_from     = "2022-02-12"
      cert_valid_to       = "2023-02-12"

      country             = "GB"
      state               = "Cheshire"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:c5:1f:4c:f4:d8:2b:c9:20:42:1e:1a:d9:3e:39:d4:90"
      )
}
