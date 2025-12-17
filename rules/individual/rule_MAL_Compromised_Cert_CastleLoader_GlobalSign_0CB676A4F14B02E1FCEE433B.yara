import "pe"

rule MAL_Compromised_Cert_CastleLoader_GlobalSign_0CB676A4F14B02E1FCEE433B {
   meta:
      description         = "Detects CastleLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-13"
      version             = "1.0"

      hash                = "9c8d22a4d79060a227f71842a2b20fa545c7b2bb87f58e3364781cf943342608"
      malware             = "CastleLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "This is an initial access tool that is frequenty used to load infostealers or remote access tools, sold as Malware-as-a-Service: https://www.ibm.com/think/x-force/dissecting-castlebot-maas-operation"

      signer              = "SURANA ENTERTAINMENT PARADISE LLP"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "0c:b6:76:a4:f1:4b:02:e1:fc:ee:43:3b"
      cert_thumbprint     = "758403C1786894D2AE11B159741A8D0D5530898E"
      cert_valid_from     = "2025-06-13"
      cert_valid_to       = "2026-06-14"

      country             = "IN"
      state               = "Rajasthan"
      locality            = "Jaipur"
      email               = "vishupsc106@gmail.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "0c:b6:76:a4:f1:4b:02:e1:fc:ee:43:3b"
      )
}
